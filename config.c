#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <string.h>

#include "pktcaptd.h"

int
config_init(struct pktcaptd_conf *conf, const char *cfgfile)
{
	struct iface	*ifp;
	int		 ret = -1;
	char		 buf[CONFIGSIZ];
	char		*ifname;
	char		*cfgs, *cfg, *ptr;
	FILE		*fp = NULL;

	TAILQ_INIT(&conf->iface_tailq);

	if ((fp = fopen(cfgfile, "r")) == NULL)
		goto done;

	memset(buf, 0, sizeof(buf));

	while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		if ((ifp = malloc(sizeof(struct iface))) == NULL)
			goto done;

		memset(ifp, 0, sizeof(*ifp));
		ifp->fd = -1;
		if ((ifname = strtok(buf, ":")) == NULL) {
			log_debug("strtok ifname");
			goto done;
		}

		for (ptr = ifname; isspace(*ptr); ptr++) {
			ifname = ptr;
		}

		if ((ptr = strchr(ifname, ' ')) != NULL) {
			*ptr = '\0';
		}

		if ((cfgs = strtok(NULL, "\n")) == NULL) {
			log_debug("strtok cfgs");
			goto done;
		}

		for (ptr = cfgs; isspace(*ptr); ptr++) {
			cfgs = ptr;
		}

		if ((ifp->ifindex = if_nametoindex(ifname)) == 0) {
			log_warnx("no such interface: [%s]", ifname);
			goto done;
		}

		if ((cfg = strtok(cfgs, " ")) == NULL)
			goto done;

		do {
			if (strcmp("mac", cfg) == 0)
				ifp->analyze_flag |= ANALYZE_L2;
			else if (strcmp("ip", cfg) == 0)
				ifp->analyze_flag |= ANALYZE_L3;
			else if (strcmp("port", cfg) == 0)
				ifp->analyze_flag |= ANALYZE_L4;
			else {
				log_warnx("unknown config value: %s", cfg);
				goto done;
			}
		} while ((cfg = strtok(NULL, " ")) != NULL);

		log_debug("IF=%s, L2=%s, L3=%s, L4=%s", ifname,
		    (ifp->analyze_flag & ANALYZE_L2) ? "enable" : "disable",
		    (ifp->analyze_flag & ANALYZE_L3) ? "enable" : "disable",
		    (ifp->analyze_flag & ANALYZE_L4) ? "enable" : "disable");
		TAILQ_INSERT_HEAD(&conf->iface_tailq, ifp, entry);
		strncpy(ifp->ifname, ifname, sizeof(ifp->ifname) -1);
		memset(buf, 0, sizeof(buf));
		ifp = NULL;
	}

	ifp = NULL;
	ret = 0;
done:
	if (ifp)
		free(ifp);

	if (ret != 0) {
		for (ifp = TAILQ_FIRST(&conf->iface_tailq); ifp;
		    ifp = TAILQ_FIRST(&conf->iface_tailq)) {
			TAILQ_REMOVE(&conf->iface_tailq, ifp, entry);
			free(ifp);
		}
	}

	return ret;
}
