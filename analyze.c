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

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pktcaptd.h"

int
mac_ntop(u_int8_t *hwaddr, char *buf, int bufsiz)
{
	return snprintf(buf, bufsiz, "%02X:%02X:%02X:%02X:%02X:%02X",
	    hwaddr[0], hwaddr[1], hwaddr[2],
	    hwaddr[3], hwaddr[4], hwaddr[5]);
}

int
ip_ntop(u_int32_t *ip, char *buf, int bufsiz)
{
	u_int8_t	*addr = (u_int8_t *)ip;
	return snprintf(buf, bufsiz, "%d.%d.%d.%d",
	    addr[0], addr[1], addr[2], addr[3]);
}

uint32_t
analyze_hash(uint32_t mask, struct flow_ptr *p)
{
	uint32_t	 key = 0, ret = 0;
	uint32_t	 src, dst;

	if (p->src.ip4addr != NULL && p->dst.ip4addr != NULL) {
		src = ntohl(*p->src.ip4addr);
		dst = *p->dst.ip4addr;
		key = src ^ dst;
	}
	ret = key & mask;
	return ret;
}

struct flow *
flowlist_lookup(struct flowlist *fl, struct flow_ptr *p)
{
	struct flow	*f = NULL;
	char		 saddr[32], daddr[32];

	TAILQ_FOREACH(f, fl, entry) {
		if (*(p->flags) != f->flags)
			continue;

		if ((*(p->flags) & FLOW_MAC) != 0
		    && memcmp(p->src.macaddr, f->src.macaddr, sizeof(f->src.macaddr)) != 0
		    && memcmp(p->dst.macaddr, f->dst.macaddr, sizeof(f->dst.macaddr)) != 0)
			continue;

		if ((*(p->flags) & FLOW_IP4) != 0
		    && memcmp(p->src.ip4addr, &f->src.ip4addr, sizeof(f->src.ip4addr)) != 0
		    && memcmp(p->src.ip4addr, &f->dst.ip4addr, sizeof(f->dst.ip4addr)) != 0)
			continue;

		if ((*(p->flags) & FLOW_IP6) != 0
		    && memcmp(p->src.ip6addr, &f->src.ip6addr, sizeof(f->src.ip6addr)) != 0
		    && memcmp(p->dst.ip6addr, &f->dst.ip6addr, sizeof(f->dst.ip6addr)) != 0)
			continue;

		if ((*(p->flags) & (FLOW_TCP | FLOW_UDP)) != 0
		    && memcmp(p->src.port, &f->src.port, sizeof(f->src.port)) != 0
		    && memcmp(p->dst.port, &f->dst.port, sizeof(f->dst.port)) != 0)
			continue;

		break;
	}

	if (f == NULL) {
		if ((f = malloc(sizeof(struct flow))) == NULL)
			goto done;

		memset(f, 0, sizeof(*f));
		f->flags = *(p->flags);

		if ((*(p->flags) & FLOW_MAC) != 0) {
			memcpy(f->src.macaddr, p->src.macaddr, sizeof(f->src.macaddr));
			memcpy(f->dst.macaddr, p->dst.macaddr, sizeof(f->dst.macaddr));
		}

		if ((*(p->flags) & FLOW_IP4) != 0) {
			memcpy(&f->src.ip4addr, p->src.ip4addr, sizeof(f->src.ip4addr));
			memcpy(&f->dst.ip4addr, p->dst.ip4addr, sizeof(f->dst.ip4addr));
			memset(saddr, 0, sizeof(saddr));
			memset(daddr, 0, sizeof(daddr));
			ip_ntop(&f->src.ip4addr, saddr, sizeof(saddr));
			ip_ntop(&f->dst.ip4addr, daddr, sizeof(daddr));
			log_debug("new flow: %s -> %s", saddr, daddr);
		}

		if ((*(p->flags) & FLOW_IP6) != 0) {
			memcpy(&f->src.ip6addr, p->src.ip6addr, sizeof(f->src.ip6addr));
			memcpy(&f->dst.ip6addr, p->dst.ip6addr, sizeof(f->dst.ip6addr));
		}

		if ((*(p->flags) & (FLOW_TCP | FLOW_UDP)) != 0) {
			memcpy(&f->src.port, p->src.port, sizeof(f->src.port));
			memcpy(&f->dst.port, p->dst.port, sizeof(f->dst.port));
		}

		TAILQ_INSERT_TAIL(fl, f, entry);
	}

done:
	return f;
}

void
flowlist_destroy(struct flowlist *fl)
{
	struct flow	*f = NULL;

	for (f = TAILQ_FIRST(fl); f != NULL; f = TAILQ_FIRST(fl)) {
		TAILQ_REMOVE(fl, f, entry);
		free(f);
	}
}

void
flowlist_clear(struct flowlist *fl)
{
	struct flow	*f;
	TAILQ_FOREACH(f, fl, entry) {
		f->count = 0;
		f->size = 0;
	}
}

uint32_t
flowlist_dump(struct flowlist *fl, int fd, const char *pfx, int tab)
{
	char		 str[PRINTSIZ];
	char		 addr[32];
	const char	*comma = pfx;
	const char	*proto_str = "unknown";
	struct flow	*f;
	int		 n = 0, i;
	int		 count = 0;
	int		 ntab = tab + 1;
	int		 len = sizeof(str);

	TAILQ_FOREACH(f, fl, entry) {
		if (f->count == 0)
			continue;
		if (f->flags == FLOW_NONE)
			continue;

		n += snprintf(str + n, len - n, "%s", comma);
		for (i = 0; i < tab; i++)
			n += snprintf(str + n, len - n, "    ");
		n += snprintf(str + n, len - n, "{\n");

		for (i = 0; i < ntab; i++)
			n += snprintf(str + n, len - n, "    ");
		n += snprintf(str + n, len - n, "\"count\":%lu,\n", f->count);
		for (i = 0; i < ntab; i++)
			n += snprintf(str + n, len - n, "    ");
		n += snprintf(str + n, len - n, "\"size\" :%lu", f->size);

		write(fd, str, n);
		memset(str, 0, len);
		n = 0;

		if (f->flags & FLOW_MAC) {
			n += snprintf(str + n, len - n, ",\n");

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			memset(addr, 0, sizeof(addr));
			mac_ntop(f->src.macaddr, addr, sizeof(addr));
			n += snprintf(str + n, len - n, "\"src_mac\" : \"%s\",\n",
			    addr);

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			memset(addr, 0, sizeof(addr));
			mac_ntop(f->dst.macaddr, addr, sizeof(addr));
			n += snprintf(str + n, len - n, "\"dst_mac\" : \"%s\"",
			    addr);

			write(fd, str, n);
			memset(str, 0, len);
			n = 0;
		}

		if (f->flags & FLOW_IP4) {
			n += snprintf(str + n, len - n, ",\n");

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			memset(addr, 0, sizeof(addr));
			ip_ntop(&f->src.ip4addr, addr, sizeof(addr));
			n += snprintf(str + n, len - n, "\"src_ip4\" : \"%s\",\n",
			    addr);

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			memset(addr, 0, sizeof(addr));
			ip_ntop(&f->dst.ip4addr, addr, sizeof(addr));
			n += snprintf(str + n, len - n, "\"dst_ip4\" : \"%s\"",
			    addr);

			write(fd, str, n);
			memset(str, 0, len);
			n = 0;
		} else if (f->flags & FLOW_IP6) {
			n += snprintf(str + n, len - n, ",\n");

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			memset(addr, 0, sizeof(addr));
			inet_ntop(AF_INET6, &f->src.ip6addr, addr, sizeof(addr));
			n += snprintf(str + n, len - n, "\"src_ip6\" : \"%s\",\n",
			    addr);

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			memset(addr, 0, sizeof(addr));
			inet_ntop(AF_INET6, &f->dst.ip6addr, addr, sizeof(addr));
			n += snprintf(str + n, len - n, "\"dst_ip6\" : \"%s\"",
			    addr);

			write(fd, str, n);
			memset(str, 0, len);
			n = 0;
		}


		if (f->flags & (FLOW_TCP | FLOW_UDP)) {
			n += snprintf(str + n, len - n, ",\n");

			if (f->flags & FLOW_TCP)
				proto_str = "tcp";
			else
				proto_str = "udp";

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			n += snprintf(str + n, len - n,
			    "\"l4proto\" : \"%s\",\n", proto_str);

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			n += snprintf(str + n, len - n, "\"src_port\" : %u,\n",
			    ntohs(f->src.port));

			for (i = 0; i < ntab; i++)
				n += snprintf(str + n, len - n, "    ");
			n += snprintf(str + n, len - n, "\"dst_port\" : %u",
			    ntohs(f->dst.port));
			write(fd, str, n);
			memset(str, 0, len);
			n = 0;
		}

		n += snprintf(str + n, len - n, "\n");
		for (i = 0; i < tab; i++)
			n += snprintf(str + n, len - n, "    ");
		n += snprintf(str + n, len - n, "}");
		write(fd, str, n);
		memset(str, 0, len);
		n = 0;
		comma = ",\n";
		count++;
	}
	return count;
}

struct analyzer *
analyzer_open(struct pktcaptd_conf *conf, struct iface *iface)
{
	struct analyzer	*a = NULL, *ret = NULL;
	int		 i;
	uint32_t	 mask, nmask;

	if ((a = malloc(sizeof(struct analyzer))) == NULL)
		goto done;

	memset(a, 0, sizeof(*a));

	if ((a->flowlist_table = malloc(sizeof(struct flowlist) * conf->flowtable_size)) == NULL)
		goto done;

	a->flowlist_table_size = conf->flowtable_size;
	for (mask = 0; nmask < a->flowlist_table_size; nmask = ((mask << 1) | 0x01)) {
		mask = nmask;
	}
	a->hash_mask = mask;
	for (i = 0; i < a->flowlist_table_size; i++) {
		TAILQ_INIT(&a->flowlist_table[i]);
	}

	strncpy(a->ifname, iface->ifname, sizeof(a->ifname) - 1);
	a->analyze_flag = iface->analyze_flag;

	ret = a;
	a = NULL;
done:
	if (a) {
		if (a->flowlist_table)
			free(a->flowlist_table);
		free(a);
	}
	return ret;
}

void
analyze(struct analyzer *a, void *bufp, int siz)
{
	struct ether_header	*eh;
	struct iphdr		*iph;
	struct ip6_hdr		*ip6h;
	struct tcphdr		*tcph;
	struct udphdr		*udph;
	int			 hdrsiz = 0;
	int			 n = 0;
	uint8_t			*buf = (uint8_t *)bufp;
	struct flow		*flow;
	struct flowlist		*flowlist;
	struct flow_ptr		 inpkt, entry;
	uint32_t		 inp_flags;
	uint16_t		 next_proto = 0;

	memset(&inpkt, 0, sizeof(inpkt));
	memset(&entry, 0, sizeof(entry));
	inp_flags = 0;
	inpkt.flags = &inp_flags;

	hdrsiz = sizeof(struct ether_header);
	if (siz < hdrsiz)
		return;
	eh = (struct ether_header *)buf;
	n += sizeof(*eh);
	if (a->analyze_flag & ANALYZE_L2) {
		inpkt.src.macaddr = eh->ether_shost;
		inpkt.dst.macaddr = eh->ether_dhost;
		*(inpkt.flags) = FLOW_MAC;
	}
	next_proto = (uint16_t)ntohs(eh->ether_type);

	switch (next_proto) {
	case ETHERTYPE_IP:
		hdrsiz = sizeof(struct iphdr);
		if (siz < (n + hdrsiz))
			goto done;
		iph = (struct iphdr *) (buf + n);
		n += hdrsiz;
		if (a->analyze_flag & ANALYZE_L3) {
			inpkt.src.ip4addr = &iph->saddr;
			inpkt.dst.ip4addr = &iph->daddr;
			*(inpkt.flags) |= FLOW_IP4;
		}
		next_proto = iph->protocol;
		break;
	case ETHERTYPE_IPV6:
		hdrsiz = sizeof(struct ip6_hdr);
		if (siz < (n + hdrsiz))
			goto done;
		ip6h = (struct ip6_hdr *)(buf + n);
		n += hdrsiz;
		if (a->analyze_flag & ANALYZE_L3) {
			inpkt.src.ip6addr = &ip6h->ip6_src;
			inpkt.dst.ip6addr = &ip6h->ip6_dst;
			*(inpkt.flags) |= FLOW_IP6;
		}
		next_proto = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		break;
	default:
		goto done;
	}

	switch (next_proto) {
	case IPPROTO_TCP:
		hdrsiz = sizeof(struct tcphdr);
		if (siz < (n + hdrsiz))
			goto done;
		tcph = (struct tcphdr *)(buf + n);
		n += hdrsiz;
		if (a->analyze_flag & ANALYZE_L4) {
			inpkt.src.port = &tcph->th_sport;
			inpkt.dst.port = &tcph->th_dport;
			*(inpkt.flags) |= FLOW_TCP;
		}
		break;
	case IPPROTO_UDP:
		hdrsiz = sizeof(struct udphdr);
		if (siz < (n + hdrsiz))
			goto done;
		udph = (struct udphdr *)(buf + n);
		n += hdrsiz;
		if (a->analyze_flag & ANALYZE_L4) {
			inpkt.src.port = &udph->uh_sport;
			inpkt.dst.port = &udph->uh_dport;
			*(inpkt.flags) |= FLOW_UDP;
		}
		break;
	default:
		goto done;
	}

done:
	flowlist = &a->flowlist_table[analyze_hash(a->hash_mask, &inpkt)];
	flow = flowlist_lookup(flowlist, &inpkt);
	flow->count ++;
	flow->size += siz;
}

void
analyzer_close(struct analyzer *a)
{
	int	 i;

	if (a == NULL)
		return;

	for (i = 0; i < a->flowlist_table_size; i++) {
		flowlist_destroy(&a->flowlist_table[i]);
	}

	free(a->flowlist_table);
	free(a);
}

void
analyzer_dump(struct analyzer *a, int fd)
{
	int		 i, n = 0, len;
	char		 str[PRINTSIZ];
	uint64_t	 total = 0;
	uint64_t	 count = 0;
	char		*comma = "\n";

	len = sizeof(str);
	n = 0;
	memset(str, 0, len);

	n += snprintf(str + n, len - n, "{\n");
	n += snprintf(str + n, len - n,
	    "    \"interface\" : \"%s\",\n" , a->ifname);
	n += snprintf(str + n, len - n,
	    "    \"flows\" : [");
	write(fd, str, n);
	n = 0;
	memset(str, 0, len);

	for (i = 0; i < a->flowlist_table_size; i++) {
		count = flowlist_dump(&a->flowlist_table[i], fd, comma, 2);
		if (count != 0)
			log_stderr("flowlist#%4d is %lu flows", i, count);

		if (count != 0)
			comma = ",\n";
		total += count;
	}

	n += snprintf(str + n, len - n, "\n    ],\n");
	n += snprintf(str + n, len - n, "    \"total_flow\" : %lu\n", total);
	n += snprintf(str + n, len - n, "}\n");
	write(fd, str, n);
}

void
analyzer_clear(struct analyzer *a)
{
	int		 i;

	for (i = 0; i < a->flowlist_table_size; i++) {
		flowlist_clear(&a->flowlist_table[i]);
	}
}
