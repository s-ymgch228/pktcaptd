#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "pktcaptd.h"

int
interface_open(struct pktcaptd_conf *conf)
{
	struct sockaddr_ll	 sll;
	struct iface		*iface;
	struct ifreq		 ifreq;
	int			 s, count = 0;

	TAILQ_FOREACH(iface, &conf->iface_tailq, entry) {
		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex = iface->ifindex;

		if (sll.sll_ifindex == 0) {
			log_warn("if_nametoindex");
			continue;
		}

		if ((s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
			log_warn("socket");
			continue;
		}

		if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
			log_warn("bind");
			close(s);
			continue;
		}

		memset(&ifreq, 0, sizeof(ifreq));
		strncpy(ifreq.ifr_name, iface->ifname, sizeof(ifreq.ifr_name) - 1);

		if (ioctl(s, SIOCGIFFLAGS, &ifreq) == -1) {
			log_warn("ioctl(SIOCGIFFLAGS)");
			close(s);
			continue;
		}

		ifreq.ifr_flags |= IFF_PROMISC;
		if (ioctl(s, SIOCSIFFLAGS, &ifreq) == -1) {
			log_warn("ioctl(SIOSIFFLAGS)");
			close(s);
			continue;
		}

		memset(&ifreq, 0, sizeof(ifreq));
		strncpy(ifreq.ifr_name, iface->ifname, sizeof(ifreq.ifr_name) - 1);
		if (ioctl(s, SIOCGIFMTU, &ifreq) == -1) {
			log_warn("ioctl(SIOCGIFMTU)");
			iface->recvbufsiz = 1500; /* ETHERMTU size */
		} else {
			iface->recvbufsiz = ifreq.ifr_mtu;
		}

		iface->recvbufsiz *= 2;

		if ((iface->recvbuf =
		    malloc(sizeof(char) * iface->recvbufsiz)) == NULL) {
			log_warn("malloc");
			close(s);
			iface->recvbufsiz = 0;
			continue;
		}

		iface->fd = s;
		count++;
	}

	return (count == 0) ? -1 : count;
}

void
interface_close(struct pktcaptd_conf *conf)
{
	struct iface	*iface;

	TAILQ_FOREACH(iface, &conf->iface_tailq, entry) {
		if (iface->fd == -1)
			continue;

		close(iface->fd);
		iface->fd = -1;
	}
}

int
interface_recv(struct iface *iface, void *buf, int bufsiz)
{
	return read(iface->fd, buf, bufsiz);
}
