#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "pktcaptd.h"

void
usage(void)
{
	fprintf(stderr, "packetcaptdctl [-S socket path]");
}

int
main(int argc, char *argv[])
{
	const char		*sockpath = SOCKET_PATH;
	struct ctrl_command	 cmd;
	struct sockaddr_un	 sun;
	int	 		 fd, ch, n;
	char			 buf[PRINTSIZ];

	while ((ch = getopt(argc, argv, "S:")) != -1) {
		switch(ch) {
		case 'S':
			sockpath = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal("socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path)-1);
	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("connect");

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd_id = CTRL_CMD_DUMP;

	write(fd, &cmd, sizeof(cmd));
	printf("%s(%d)\n", __func__, __LINE__);

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		fwrite(buf, sizeof(char), n, stdout);
	}

	close(fd);
}
