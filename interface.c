#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

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
		sll.sll_ifindex = if_nametoindex(iface->ifname);

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
		ifreq.ifr_ifindex = sll.sll_ifindex;
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
