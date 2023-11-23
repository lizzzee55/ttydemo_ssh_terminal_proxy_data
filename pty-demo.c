/**
 * gcc -o pty-demo pty-demo.c
 * pty-demo bash
 */

#define _XOPEN_SOURCE	600	/* Single UNIX Specification, Version 3 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>		/* for convenience */
#include <stdlib.h>		/* for convenience */
#include <stddef.h>		/* for offsetof */
#include <string.h>		/* for convenience */
#include <unistd.h>		/* for convenience */
#include <signal.h>		/* for SIG_ERR */
#include <termios.h>

#include <sys/types.h>		/* some systems still require this */
#include <sys/stat.h>
#include <sys/termios.h>	/* for winsize */
#include <sys/ioctl.h>	/* for struct winsize */

#define	BUFFSIZE	512

static volatile sig_atomic_t	sigcaught;	/* set by signal handler */

/*
 * The child sends us SIGTERM when it gets EOF on the pty slave or
 * when read() fails.  We probably interrupted the read() of ptym.
 */
static void
sig_term(int signo)
{
	sigcaught = 1;		/* just set flag and return */
}

ssize_t             /* Write "n" bytes to a descriptor  */
writen(int fd, const void *ptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;

	nleft = n;
	while (nleft > 0) {
		if ((nwritten = write(fd, ptr, nleft)) < 0) {
			if (nleft == n)
				return(-1); /* error, return -1 */
			else
				break;      /* error, return amount written so far */
		} else if (nwritten == 0) {
			break;
		}
		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n - nleft);      /* return >= 0 */
}

void
signal_intr(int signo, void func(int))
{
	struct sigaction	act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
#ifdef	SA_INTERRUPT
	act.sa_flags |= SA_INTERRUPT;
#endif
	if (sigaction(signo, &act, &oact) < 0)
		fprintf(stderr, "signal_intr error for SIGTERM");
}

void
loop(int ptym, int ignoreeof)
{
	pid_t	child;
	int		nread;
	char	buf[BUFFSIZE];

	if ((child = fork()) < 0) {
		fprintf(stderr, "fork error");
	} else if (child == 0) {	/* child copies stdin to ptym */
		for ( ; ; ) {
			if ((nread = read(STDIN_FILENO, buf, BUFFSIZE)) < 0)
				fprintf(stderr, "read error from stdin");
			else if (nread == 0)
				break;		/* EOF on stdin means we're done */
			if (writen(ptym, buf, nread) != nread)
				fprintf(stderr, "writen error to master pty");
		}

		/*
		 * We always terminate when we encounter an EOF on stdin,
		 * but we notify the parent only if ignoreeof is 0.
		 */
		if (ignoreeof == 0)
			kill(getppid(), SIGTERM);	/* notify parent */
		exit(0);	/* and terminate; child can't return */
	}

	/*
	 * Parent copies ptym to stdout.
	 */
	signal_intr(SIGTERM, sig_term);

	for ( ; ; ) {
		if ((nread = read(ptym, buf, BUFFSIZE)) <= 0)
			break;		/* signal caught, error, or EOF */
		if (writen(STDOUT_FILENO, buf, nread) != nread)
			fprintf(stderr, "writen error to stdout");
	}

	/*
	 * There are three ways to get here: sig_term() below caught the
	 * SIGTERM from the child, we read an EOF on the pty master (which
	 * means we have to signal the child to stop), or an error.
	 */
	if (sigcaught == 0)	/* tell child if it didn't send us the signal */
		kill(child, SIGTERM);
}

int
ptym_open(char *pts_name, int pts_namesz)
{
	char	*ptr;
	int		fdm;

	/*
	 * Return the name of the master device so that on failure
	 * the caller can print an error message.  Null terminate
	 * to handle case where string length > pts_namesz.
	 */
	strncpy(pts_name, "/dev/ptmx", pts_namesz);
	pts_name[pts_namesz - 1] = '\0';

	fdm = posix_openpt(O_RDWR);
	if (fdm < 0)
		return(-1);
	if (grantpt(fdm) < 0) {		/* grant access to slave */
		close(fdm);
		return(-2);
	}
	if (unlockpt(fdm) < 0) {	/* clear slave's lock flag */
		close(fdm);
		return(-3);
	}
	if ((ptr = ptsname(fdm)) == NULL) {	/* get slave's name */
		close(fdm);
		return(-4);
	}

	/*
	 * Return name of slave.  Null terminate to handle case
	 * where strlen(ptr) > pts_namesz.
	 */
	strncpy(pts_name, ptr, pts_namesz);
	pts_name[pts_namesz - 1] = '\0';
	return(fdm);			/* return fd of master */
}

int
ptys_open(char *pts_name)
{
	int fds;

	if ((fds = open(pts_name, O_RDWR)) < 0)
		return(-5);
	return(fds);
}

pid_t
pty_fork(int *ptrfdm, char *slave_name, int slave_namesz,
		 const struct termios *slave_termios,
		 const struct winsize *slave_winsize)
{
	int		fdm, fds;
	pid_t	pid;
	char	pts_name[20];

	if ((fdm = ptym_open(pts_name, sizeof(pts_name))) < 0)
		fprintf(stderr, "can't open master pty: %s, error %d", pts_name, fdm);

	if (slave_name != NULL) {
		/*
		 * Return name of slave.  Null terminate to handle case
		 * where strlen(pts_name) > slave_namesz.
		 */
		strncpy(slave_name, pts_name, slave_namesz);
		slave_name[slave_namesz - 1] = '\0';
	}

	if ((pid = fork()) < 0) {
		return(-1);
	} else if (pid == 0) {		/* child */
		if (setsid() < 0)
			fprintf(stderr, "setsid error");

		/*
		 * System V acquires controlling terminal on open().
		 */
		if ((fds = ptys_open(pts_name)) < 0)
			fprintf(stderr, "can't open slave pty");
		close(fdm);		/* all done with master in child */

#if	defined(TIOCSCTTY)
		/*
		 * TIOCSCTTY is the BSD way to acquire a controlling terminal.
		 */
		if (ioctl(fds, TIOCSCTTY, (char *)0) < 0)
			fprintf(stderr, "TIOCSCTTY error");
#endif
		/*
		 * Set slave's termios and window size.
		 */
		if (slave_termios != NULL) {
			if (tcsetattr(fds, TCSANOW, slave_termios) < 0)
				fprintf(stderr, "tcsetattr error on slave pty");
		}
		if (slave_winsize != NULL) {
			if (ioctl(fds, TIOCSWINSZ, slave_winsize) < 0)
				fprintf(stderr, "TIOCSWINSZ error on slave pty");
		}

		/*
		 * Slave becomes stdin/stdout/stderr of child.
		 */
		if (dup2(fds, STDIN_FILENO) != STDIN_FILENO)
			fprintf(stderr, "dup2 error to stdin");
		if (dup2(fds, STDOUT_FILENO) != STDOUT_FILENO)
			fprintf(stderr, "dup2 error to stdout");
		if (dup2(fds, STDERR_FILENO) != STDERR_FILENO)
			fprintf(stderr, "dup2 error to stderr");
		if (fds != STDIN_FILENO && fds != STDOUT_FILENO &&
		  fds != STDERR_FILENO)
			close(fds);
		return(0);		/* child returns 0 just like fork() */
	} else {					/* parent */
		*ptrfdm = fdm;	/* return fd of master */
		return(pid);	/* parent returns pid of child */
	}
}

static struct termios		save_termios;
static int					ttysavefd = -1;
static enum { RESET, RAW, CBREAK }	ttystate = RESET;

int
tty_raw(int fd)		/* put terminal into a raw mode */
{
	int				err;
	struct termios	buf;

	if (ttystate != RESET) {
		errno = EINVAL;
		return(-1);
	}
	if (tcgetattr(fd, &buf) < 0)
		return(-1);
	save_termios = buf;	/* structure copy */

	/*
	 * Echo off, canonical mode off, extended input
	 * processing off, signal chars off.
	 */
	buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);

	/*
	 * No SIGINT on BREAK, CR-to-NL off, input parity
	 * check off, don't strip 8th bit on input, output
	 * flow control off.
	 */
	buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

	/*
	 * Clear size bits, parity checking off.
	 */
	buf.c_cflag &= ~(CSIZE | PARENB);

	/*
	 * Set 8 bits/char.
	 */
	buf.c_cflag |= CS8;

	/*
	 * Output processing off.
	 */
	buf.c_oflag &= ~(OPOST);

	/*
	 * Case B: 1 byte at a time, no timer.
	 */
	buf.c_cc[VMIN] = 1;
	buf.c_cc[VTIME] = 0;
	if (tcsetattr(fd, TCSAFLUSH, &buf) < 0)
		return(-1);

	/*
	 * Verify that the changes stuck.  tcsetattr can return 0 on
	 * partial success.
	 */
	if (tcgetattr(fd, &buf) < 0) {
		err = errno;
		tcsetattr(fd, TCSAFLUSH, &save_termios);
		errno = err;
		return(-1);
	}
	if ((buf.c_lflag & (ECHO | ICANON | IEXTEN | ISIG)) ||
	  (buf.c_iflag & (BRKINT | ICRNL | INPCK | ISTRIP | IXON)) ||
	  (buf.c_cflag & (CSIZE | PARENB | CS8)) != CS8 ||
	  (buf.c_oflag & OPOST) || buf.c_cc[VMIN] != 1 ||
	  buf.c_cc[VTIME] != 0) {
		/*
		 * Only some of the changes were made.  Restore the
		 * original settings.
		 */
		tcsetattr(fd, TCSAFLUSH, &save_termios);
		errno = EINVAL;
		return(-1);
	}

	ttystate = RAW;
	ttysavefd = fd;
	return(0);
}

int
tty_reset(int fd)		/* restore terminal's mode */
{
	if (ttystate == RESET)
		return(0);
	if (tcsetattr(fd, TCSAFLUSH, &save_termios) < 0)
		return(-1);
	ttystate = RESET;
	return(0);
}

void
tty_atexit(void)		/* can be set up by atexit(tty_atexit) */
{
	if (ttysavefd >= 0)
		tty_reset(ttysavefd);
}

int
main(int argc, char *argv[])
{
	struct termios	orig_termios;
	struct winsize	size;
	pid_t			pid;
	int				fdm, c, ignoreeof, interactive, noecho, verbose;
	char			slave_name[20];

        if (tcgetattr(STDIN_FILENO, &orig_termios) < 0)
                fprintf(stderr, "tcgetattr error on stdin");
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, (char *) &size) < 0)
                fprintf(stderr, "TIOCGWINSZ error");
        pid = pty_fork(&fdm, slave_name, sizeof(slave_name),
            &orig_termios, &size);

	if (pid < 0) {
		fprintf(stderr, "fork error");
	}

        if (pid == 0) {
            /* child */
            if (execvp(argv[1], &argv[1]) < 0)
                    fprintf(stderr, "can't execute: %s", argv[1]);
	}

        fprintf(stderr, "slave name = %s\n", slave_name);

        if (tty_raw(STDIN_FILENO) < 0)	/* user's tty to raw mode */
                fprintf(stderr, "tty_raw error");
        if (atexit(tty_atexit) < 0)		/* reset user's tty on exit */
                fprintf(stderr, "atexit error");

	loop(fdm, ignoreeof);	/* copies stdin -> ptym, ptym -> stdout */

	exit(0);
}
