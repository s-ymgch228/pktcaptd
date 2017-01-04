#include <stdlib.h>
#include <string.h>

#include "pktcaptd.h"

int
config_init(struct pktcaptd_conf *conf)
{
	struct iface		*ifp;
	int ret = -1;

	TAILQ_INIT(&conf->iface_tailq);


	if ((ifp = malloc(sizeof(struct iface))) == NULL)
		goto done;

	memset(ifp, 0, sizeof(*ifp));
	ifp->fd = -1;
	strncpy(ifp->ifname, "enp13s0f0", sizeof(ifp->ifname) -1);
	TAILQ_INSERT_HEAD(&conf->iface_tailq, ifp, entry);

	conf->host_max = 64;
	conf->control_timeout = 5;

	ret = 0;
done:
	if (ret != 0) {
		for (ifp = TAILQ_FIRST(&conf->iface_tailq); ifp;
		    ifp = TAILQ_FIRST(&conf->iface_tailq)) {
			TAILQ_REMOVE(&conf->iface_tailq, ifp, entry);
			free(ifp);
		}
	}

	return ret;
}
