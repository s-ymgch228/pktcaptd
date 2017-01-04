#ifndef _PIDFILE_H_
#define _PIDFILE_H_

#include <sys/param.h>

#define PFH_PATH_LEN	1024

struct pidfh {
	int	 pfh_fd;
	char	 pfh_path[PFH_PATH_LEN];
	pid_t	 pfh_pid;
};

struct pidfh * pidfile_open(const char *, mode_t, pid_t *);
int pidfile_write(struct pidfh *);
int pidfile_remove(struct pidfh *);
#endif
