#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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

	if (p->src.ip4addr != NULL)
		key = ntohl(*(p->src.ip4addr));
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
	int			 hdrsiz = 0;
	int			 n = 0;
	uint8_t			*buf = (uint8_t *)bufp;
	struct flow		*flow;
	struct flowlist		*flowlist;
	struct flow_ptr		 inpkt, entry;
	uint32_t		 inp_flags;

	memset(&inpkt, 0, sizeof(inpkt));
	memset(&entry, 0, sizeof(entry));
	inpkt.flags = &inp_flags;

	hdrsiz = sizeof(struct ether_header);
	if (siz < hdrsiz)
		return;
	eh = (struct ether_header *)buf;
	n += sizeof(*eh);
	inpkt.src.macaddr = eh->ether_shost;
	inpkt.dst.macaddr = eh->ether_dhost;
	*(inpkt.flags) = FLOW_MAC;

	switch (ntohs(eh->ether_type)) {
	case ETHERTYPE_IP:
		hdrsiz = sizeof(struct iphdr);
		if (siz < (n + hdrsiz))
			goto done;
		iph = (struct iphdr *) (buf + n);
		n += hdrsiz;
		inpkt.src.ip4addr = &iph->saddr;
		inpkt.dst.ip4addr = &iph->daddr;
		*(inpkt.flags) |= FLOW_IP4;
		break;
	case ETHERTYPE_IPV6:
		hdrsiz = sizeof(struct ip6_hdr);
		if (siz < (n + hdrsiz))
			goto done;
		ip6h = (struct ip6_hdr *)(buf + n);
		n += hdrsiz;
		inpkt.src.ip6addr = &ip6h->ip6_src;
		inpkt.dst.ip6addr = &ip6h->ip6_dst;
		*(inpkt.flags) |= FLOW_IP6;
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
