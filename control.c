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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "pktcaptd.h"

struct control *
control_open(struct pktcaptd_conf *conf, const char *sockpath)
{
	struct control		*ctrl = NULL, *ret = NULL;
	struct sockaddr_un	 sun;
	int			 pathlen = 0;

	if ((ctrl = malloc(sizeof(struct control))) == NULL)
		goto done;

	memset(ctrl, 0, sizeof(*ctrl));


	if ((ctrl->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		goto done;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path) - 1);
	unlink(sun.sun_path);

	if (bind(ctrl->fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		goto done;

	if (listen(ctrl->fd, CONTROL_CLIENT_NUM) == -1)
		goto done;

	pathlen = strlen(sun.sun_path) + 1;
	if ((ctrl->sockpath = malloc(pathlen)) == NULL)
		goto done;
	memset(ctrl->sockpath, 0, pathlen);
	strncpy(ctrl->sockpath, sun.sun_path, pathlen - 1);

	ctrl->conf = conf;
	ctrl->timeout = conf->control_timeout;
	ret = ctrl;
	ctrl = NULL;
done:
	if (ctrl) {
		if (ctrl->sockpath)
			free(ctrl->sockpath);
		if (ctrl->fd != -1)
			close(ctrl->fd);
		free(ctrl);
	}

	return ret;
}

struct control *
control_accept(struct control *ctrl)
{
	struct sockaddr_un	 client;
	struct control		 *ctrl_cli, *ret = NULL;
	socklen_t		 cli_len;

	if ((ctrl_cli = malloc(sizeof(struct control))) == NULL)
		goto done;

	memset(ctrl_cli, 0, sizeof(*ctrl_cli));
	ctrl_cli->fd = -1;
	ctrl_cli->timeout = ctrl->timeout;
	ctrl_cli->conf = ctrl->conf;
	cli_len = sizeof(client);

	if ((ctrl_cli->fd = accept(ctrl->fd, (struct sockaddr *)&client,
	    &cli_len)) == -1) {
		goto done;
	}

	ret = ctrl_cli;
	ctrl_cli = NULL;

done:
	if (ctrl_cli) {
		if (ctrl_cli->fd != -1)
			close(ctrl_cli->fd);
		free(ctrl_cli);
	}

	return ret;
}

int
control_recv(struct control *cli, struct ctrl_command *buf)
{
	return read(cli->fd, buf, sizeof(*buf));
}

void
control_client_remove(struct control *cli)
{
	if (cli->fd != -1)
		close(cli->fd);

	free(cli);
}

void
control_close(struct control *ctrl)
{
	if (ctrl->sockpath)
		unlink(ctrl->sockpath);
	control_client_remove(ctrl);
}
