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

	if ((ctrl = malloc(sizeof(struct control))) == NULL)
		goto done;

	memset(ctrl, 0, sizeof(*ctrl));

	if ((ctrl->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		goto done;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
	unlink(sun.sun_path);

	if (bind(ctrl->fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		goto done;

	if (listen(ctrl->fd, CONTROL_CLIENT_NUM) == -1)
		goto done;

	ctrl->conf = conf;
	ctrl->timeout = conf->control_timeout;
	ret = ctrl;
	ctrl = NULL;
done:
	if (ctrl) {
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
