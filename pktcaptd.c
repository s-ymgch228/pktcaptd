#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <event.h>

#include "libutil.h"
#include "pktcaptd.h"

volatile uint64_t recvcnt = 0;
void recvpkt(int , short, void *);
void control_cb(int, short, void *);
void control_client_cb(int, short, void *);

static void
sighdlr(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		event_loopbreak();
	}

}

void
usage(void)
{
	fprintf(stderr, "pktcaptd [-d] [-P pidfile] [-S socket]\n");
	exit(1);
}


int
main(int argc, char *argv[])
{
	struct pktcaptd_conf	 lconf;
	const char		*pidfile = PIDFILE_PATH;
	const char		*ctrlsock = SOCKET_PATH;
	int			 ch;
	struct pidfh		*pfh;
	pid_t			 pid;
	struct event		 ev_sigint, ev_sigterm;
	struct iface		*iface;
	struct control		*ctrl;

	memset(&lconf, 0, sizeof(lconf));

	while ((ch = getopt(argc, argv, "dP:S:")) != -1) {
		switch (ch) {
		case 'd':
			lconf.debug = 2;
			break;
		case 'P':
			pidfile = optarg;
			break;
		case 'S':
			ctrlsock = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();

	log_init(lconf.debug ? lconf.debug : 1, LOG_DAEMON);

	if (daemon(1, 0))
		fatal("daemon");

	if (config_init(&lconf) == -1)
		fatal("config_init");

	pid = getpid();
	if ((pfh = pidfile_open(pidfile, 0644, &pid)) == NULL)
		fatal("pidfile_open(%s)", pidfile);

	if (pidfile_write(pfh) == -1)
		fatal("pidfile_write");

	event_init();
	signal_set(&ev_sigint, SIGINT, sighdlr, &lconf);
	signal_set(&ev_sigterm, SIGTERM, sighdlr, &lconf);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	if (interface_open(&lconf) == -1)
		fatal("interface_init");
	if ((ctrl = control_open(&lconf, ctrlsock)) == NULL)
		fatal("control(%s)", ctrlsock);

	event_set(&ctrl->event, ctrl->fd, EV_READ | EV_PERSIST,
	    control_cb, ctrl);
	event_add(&ctrl->event, NULL);

	TAILQ_FOREACH(iface, &lconf.iface_tailq, entry) {
		if (iface->fd == -1)
			continue;

		if ((iface->analyzer = analyzer_open(&lconf, iface)) == NULL)
			log_warn("analyzer_open");

		event_set(&iface->event, iface->fd,
		    EV_READ | EV_PERSIST, recvpkt, iface);
		event_add(&iface->event, NULL);
	}

	log_info("start pktcaptd");

	event_dispatch();

	TAILQ_FOREACH(iface, &lconf.iface_tailq, entry) {
		analyzer_close(iface->analyzer);
	}

	interface_close(&lconf);
	pidfile_remove(pfh);

	log_info("exit pktcaptd");
	return 0;
}

void
recvpkt(int fd, short event, void *arg)
{
	char		 buf[BUFSIZ];
	int		 n;
	struct iface	*iface= (struct iface *)arg;

	recvcnt ++;
	n = interface_recv(iface, buf, sizeof(buf));
	if (iface->analyzer)
		analyze(iface->analyzer, buf, n);
}

void
control_cb(int fd, short event, void *arg)
{
	struct control		*ctrl = (struct control *)arg;
	struct control		*cli;
	struct timeval		 timeout, *to = NULL;

	if ((cli = control_accept(ctrl)) == NULL) {
		log_warn("control_accept");
		return;
	}

	if (cli->timeout != 0) {
		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = cli->timeout;
		to = &timeout;
	}

	event_set(&cli->event, cli->fd, EV_READ,
	    control_client_cb, cli);
	event_add(&cli->event, to);
}

void
control_client_cb(int fd, short event, void *arg)
{
	struct control		*cli = (struct control *)arg;
	struct	iface		*iface;
	struct pktcaptd_conf	*conf;
	struct ctrl_command	 cmd;
	int			 n;
	if (event != EV_READ)
		goto done;

	conf = cli->conf;

	memset(&cmd, 0, sizeof(cmd));
	if ((n = control_recv(cli, &cmd)) != sizeof(cmd)) {
		log_warnx("command recv size %d != %lu",
		    n, sizeof(cmd));
		goto done;
	}

	log_debug("recv command: %d\n", cmd.cmd_id);

	switch (cmd.cmd_id) {
	case CTRL_CMD_DUMP:
		TAILQ_FOREACH(iface, &conf->iface_tailq, entry) {
			analyzer_dump(iface->analyzer, cli->fd);
		}
		break;
	case CTRL_CMD_CLEAR:
		TAILQ_FOREACH(iface, &conf->iface_tailq, entry) {
			analyzer_clear(iface->analyzer);
		}
		break;
	case CTRL_CMD_QUIT:
		event_loopbreak();
		break;
	default:
		log_warnx("unknown command %d\n", cmd.cmd_id);
	}

done:
	control_client_remove(cli);
}
