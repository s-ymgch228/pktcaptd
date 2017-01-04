#ifndef _PKTCAPTD_H_
#define _PKTCAPTD_H_

#include <sys/queue.h>
#include <net/if.h>
#include <event.h>

#ifndef PIDFILE_PATH
#define PIDFILE_PATH	"/var/run/pktcaptd.pid"
#endif

#ifndef SOCKET_PATH
#define SOCKET_PATH	"/var/run/pktcaptd.sock"
#endif

#ifndef CNTROL_CLIENT_NUM
#define CONTROL_CLIENT_NUM	5
#endif

#define PRINTSIZ	2048


enum ctrl_cmd_id {
	CTRL_CMD_DUMP = 1,
	CTRL_CMD_CLEAR,
	CTRL_CMD_QUIT,
	CTRL_CMD_NONE
};

struct pktcaptd_conf;

TAILQ_HEAD(dest_list, dest);

struct dest {
	sa_family_t		 af;
	TAILQ_ENTRY(dest)	 entry;
	unsigned char		 addr[32];
	uint64_t		 count;
	struct dest_list	 next_hdr;
};

struct host {
	int			 af;
	int64_t			 src;
	u_int8_t		 macaddr[32];
	uint32_t		 ipaddr;
	struct in6_addr		 ip6addr;
	struct dest_list	 dest_list;
};

struct ctrl_command {
	int			 cmd_id;
};

struct control {
	int			 fd;
	struct event		 event;
	int			 timeout;
	struct pktcaptd_conf	*conf;
};

struct analyzer {
	int		 other;
	int		 host_max;
	struct host	*host;
	int		 no_buffer;
	char		 ifname[IF_NAMESIZE];
};

struct iface {
	TAILQ_ENTRY(iface)	 entry;
	char			 ifname[IF_NAMESIZE];
	int			 fd;
	struct event		 event;
	struct analyzer		*analyzer;
};

struct pktcaptd_conf {
	int				 debug;
	int				 host_max;
	int				 control_timeout;
	TAILQ_HEAD(iface_list, iface)	 iface_tailq;
};

void	log_init(int, int);
void	log_procinit(const char *);
void	log_verbose(int);
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warnx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_stderr(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));

int config_init(struct pktcaptd_conf *);
int interface_open(struct pktcaptd_conf *);
void interface_close(struct pktcaptd_conf *);
int interface_recv(struct iface *, void *, int);
struct analyzer * analyzer_open(struct pktcaptd_conf *, struct iface *);
void analyze(struct analyzer *, void *, int);
void analyzer_close(struct analyzer *);
void analyzer_dump(struct analyzer *, int fd);
void analyzer_clear(struct analyzer *);
struct control * control_open(struct pktcaptd_conf *, const char *);
struct control * control_accept(struct control *);
int control_recv(struct control *, struct ctrl_command *);
void control_client_remove(struct control *);
#endif
