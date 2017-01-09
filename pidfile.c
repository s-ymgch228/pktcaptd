/*
 * Copyright (c) 2017, Shoichi Yamaguchi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
