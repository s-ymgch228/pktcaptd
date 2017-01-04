#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "pktcaptd.h"

struct command {
	const char	*str;
	int		 id;
} commands[] = {
	{.str = "dump", .id = CTRL_CMD_DUMP},
	{.str = "clear", .id = CTRL_CMD_CLEAR},
	{.str = "quit", .id = CTRL_CMD_QUIT},
	{.str = NULL, .id = CTRL_CMD_NONE},
};

void
usage(void)
{
	int	 i;
	char	*comma = "";

	fprintf(stderr, "pktcaptdctl [-S socket path] <command ... >\n");
	fprintf(stderr, "    command: ");
	for (i = 0; commands[i].str != NULL; i++) {
		fprintf(stderr, "%s%s", comma, commands[i].str);
		comma = ", ";
	}
	fprintf(stderr, "\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	const char		*sockpath = SOCKET_PATH;
	struct ctrl_command	 cmd;
	struct sockaddr_un	 sun;
	struct command		*cmd_str;
	int	 		 fd, ch, n;
	int			 i, arg;
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

	if (argc < 1) {
		usage();
	}

	for (arg = 0; arg < argc; arg ++) {
		cmd_str = NULL;
		for (i=0; commands[i].str != NULL; i++) {
			if (strcmp(commands[i].str, argv[arg]) == 0) {
				cmd_str = &commands[i];
				break;
			}
		}

		if (cmd_str == NULL) {
			fprintf(stderr, "%s is unsupported\n", argv[arg]);
			usage();
		}

		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
			fatal("socket");

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path)-1);
		if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
			fatal("connect");

		memset(&cmd, 0, sizeof(cmd));
		cmd.cmd_id = cmd_str->id;

		write(fd, &cmd, sizeof(cmd));

		while ((n = read(fd, buf, sizeof(buf))) > 0) {
			fwrite(buf, sizeof(char), n, stdout);
		}

		close(fd);

	}

}
