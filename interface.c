/*
 * Copyright (c) 2017, Shoichi Yamaguchi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
