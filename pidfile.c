#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libutil.h"

struct pidfh *
pidfile_open(const char *path, mode_t mode, pid_t *pidptr)
{
	int		 fd;
	struct pidfh	*ptr = NULL;

	if ((fd = open(path, O_RDWR | O_CREAT, mode)) == -1)
		goto done;


	if (flock(fd, LOCK_EX|LOCK_NB) == -1)
		goto done;

	if ((ptr = malloc(sizeof(struct pidfh))) == NULL)
		goto done;

	memset(ptr, 0, sizeof(*ptr));

	ptr->pfh_fd = fd;
	fd = -1;
	ptr->pfh_pid = *pidptr;
	strncpy(ptr->pfh_path, path, sizeof(ptr->pfh_path));

done:
	if (fd != -1)
		close(fd);

	return ptr;
}

int
pidfile_write(struct pidfh *pfh)
{
	int	 ret, n = 0;
	char	 buf[BUFSIZ];

	if (pfh == NULL)
		return -1;

	memset(buf, 0, sizeof(buf));

	n = snprintf(buf, sizeof(buf), "%d", (int)pfh->pfh_pid);
	ret = write(pfh->pfh_fd, buf, n);

	return (ret <= 0) ? -1 : 0;
}

int
pidfile_remove(struct pidfh *pfh)
{
	if (pfh == NULL)
		return -1;

	if (flock(pfh->pfh_fd, LOCK_UN) == -1)
		return -1;

	unlink(pfh->pfh_path);
	return 0;
}
