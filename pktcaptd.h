#ifndef _PKTCAPTD_H_
#define _PKTCAPTD_H_

#include <sys/queue.h>
#include <net/if.h>
#include <net/ethernet.h>
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

#ifndef CFGFILE_PATH
#define CFGFILE_PATH	"/etc/pktcaptd.conf"
#endif

#ifndef CTRL_TIMEOUTMAX
#define CTRL_TIMEOUTMAX	5
#endif

#define FLOWTABLE_STR		"512"
#define CTRL_TIMEOUT_STR	"5"

#define PRINTSIZ	2048
#define CONFIGSIZ	2048


struct pktcaptd_conf;

TAILQ_HEAD(flowlist, flow);

enum flow_flag{
	FLOW_NONE	= 0x0000,
	FLOW_MAC	= 0x0001,
	FLOW_IP4	= 0x0002,
	FLOW_IP6	= 0x0004,
	FLOW_TCP	= 0x0008,
	FLOW_UDP	= 0x0010
};

struct flow {
	TAILQ_ENTRY(flow)	 entry;
	uint32_t		 flags;
	uint64_t		 count;
	uint64_t		 size;
	struct {
		uint8_t		 macaddr[ETH_ALEN];
		uint32_t	 ip4addr;
		struct in6_addr	 ip6addr;
		uint16_t	 port;
	} src, dst;
};

struct flow_ptr {
	uint32_t		*flags;
	struct {
		uint8_t		*macaddr;
		uint32_t	*ip4addr;
		struct in6_addr	*ip6addr;
		uint16_t	*port;
	} src, dst;
};

enum ctrl_cmd_id {
	CTRL_CMD_DUMP	= 1,
	CTRL_CMD_CLEAR,
	CTRL_CMD_QUIT,
	CTRL_CMD_NONE
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

enum analyze_flag {
	ANALYZE_L2	= 0x000001,
	ANALYZE_L3	= 0x000002,
	ANALYZE_L4	= 0x000004,
	ANALYZE_NONE	= 0x000000
};

struct analyzer {
	struct flowlist	*flowlist_table;
	int		 flowlist_table_size;
	char		 ifname[IF_NAMESIZE];
	uint32_t	 hash_mask;
	uint32_t	 analyze_flag;
};

struct iface {
	TAILQ_ENTRY(iface)	 entry;
	char			 ifname[IF_NAMESIZE];
	int			 fd;
	struct event		 event;
	struct analyzer		*analyzer;
	unsigned int		 ifindex;
	uint32_t		 analyze_flag;
	char			*recvbuf;
	uint32_t		 recvbufsiz;
};

struct pktcaptd_conf {
	int				 debug;
	uint32_t			 flowtable_size;
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

int config_init(struct pktcaptd_conf *, const char *);
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

#ifndef _HAVE_STRTONUM_
long long strtonum(const char *, long long, long long, const char **);
#endif

#endif
