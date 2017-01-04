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

struct dest *
dest_lookup(struct dest_list *dl, int af, void *cmp, int cmpsiz)
{
	struct dest	*dest = NULL;
	TAILQ_FOREACH(dest, dl, entry) {
		if (dest->af != af)
			continue;
		if (memcmp(dest->addr, cmp, cmpsiz) == 0)
			break;
	}

	if (dest == NULL) {
		if ((dest = malloc(sizeof(struct dest))) == NULL)
			goto done;

		memset(dest, 0, sizeof(*dest));
		TAILQ_INIT(&dest->next_hdr);
		memcpy(dest->addr, cmp, cmpsiz);
		dest->af = af;
		TAILQ_INSERT_TAIL(dl, dest, entry);
	}
done:
	return dest;
}

void
dest_list_destroy(struct dest_list *dl)
{
	struct dest	*dest = NULL;

	for (dest = TAILQ_FIRST(dl); dest != NULL; dest = TAILQ_FIRST(dl)) {
		TAILQ_REMOVE(dl, dest, entry);
		dest_list_destroy(&dest->next_hdr);

		free(dest);
	}
}

int
dest_list_empty(struct dest_list *dl)
{
	struct dest	*dest;
	int		 total = 0;
	TAILQ_FOREACH(dest, dl, entry) {
		total += dest->count;
	}

	return (total == 0) ? 1 : 0;
}

struct analyzer *
analyzer_open(struct pktcaptd_conf *conf, struct iface *iface)
{
	struct analyzer	*a = NULL, *ret = NULL;
	int		 i;

	if ((a = malloc(sizeof(struct analyzer))) == NULL)
		goto done;

	memset(a, 0, sizeof(*a));

	if ((a->host = malloc(sizeof(struct host) * conf->host_max)) == NULL)
		goto done;

	a->host_max = conf->host_max;
	memset(a->host, 0, sizeof(struct host) * a->host_max);
	for (i = 0; i < a->host_max; i++) {
		a->host[i].src = -1;
		TAILQ_INIT(&a->host[i].dest_list);
	}

	strncpy(a->ifname, iface->ifname, sizeof(a->ifname) - 1);

	ret = a;
	a = NULL;
done:
	if (a) {
		if (a->host)
			free(a->host);
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
	struct host		*host = NULL;
	struct dest		*dest = NULL;
	struct dest_list	*dest_list;
	int			 offset = 0;
	int			 af = AF_PACKET;
	int64_t			 src = 0;
	int			 hdrsiz = 0;
	int			 quit, i;
	uint8_t			*buf = (uint8_t *)bufp;

	if (siz < sizeof(struct ether_header))
		return;

	eh = (struct ether_header *)buf;
	memcpy(&src, eh->ether_shost, sizeof(eh->ether_shost));

	for (i = 0; i < a->host_max; i++) {
		if (a->host[i].src == -1) {
			a->host[i].src = src;
			memcpy(a->host[i].macaddr, eh->ether_shost,
			    sizeof(eh->ether_shost));
		}

		if (a->host[i].src == src) {
			host = &a->host[i];
			break;
		}
	}

	if (host == NULL) {
		if (a->no_buffer == 0) {
			log_warnx("no host buffer (bufsiz=%d)",
			    a->host_max);
			a->no_buffer = 1;
		}
		return;
	}

	dest_list = &host->dest_list;
	quit = 0;

	while (quit == 0) {
		switch (af) {
		case AF_PACKET:
			hdrsiz = sizeof(*eh);
			if (siz < hdrsiz + offset)
				break;

			eh = (struct ether_header *)(buf + offset);
			dest = dest_lookup(dest_list, af, eh->ether_dhost,
			    sizeof(eh->ether_dhost));
			if (dest) {
				dest->count++;
				dest_list = &dest->next_hdr;
			} else
				quit = 1;

			switch (ntohs(eh->ether_type)) {
			case ETHERTYPE_IP:
				af = AF_INET;
				break;
			case ETHERTYPE_IPV6:
				af = AF_INET6;
			default:
				af = AF_UNSPEC;
			}
			break;
		case AF_INET:
			hdrsiz = sizeof(*iph);
			if (siz < hdrsiz + offset)
				break;

			iph = (struct iphdr *)(buf + offset);
			dest = dest_lookup(dest_list, af, &iph->daddr,
			    sizeof(iph->daddr));

			if (dest) {
				dest->count++;
				dest_list = NULL;
			}

			if (host->af == AF_UNSPEC) {
				host->af = af;
				host->ipaddr = iph->saddr;
			}
			af = AF_UNSPEC;
			break;
		case AF_INET6:
			hdrsiz = sizeof(*ip6h);
			if (siz < hdrsiz + offset)
				break;

			ip6h = (struct ip6_hdr *)buf + offset;
			dest = dest_lookup(dest_list, af, ip6h->ip6_dst.s6_addr,
			    sizeof(ip6h->ip6_dst.s6_addr));

			if (dest) {
				dest->count++;
				dest_list = NULL;
			}

			if (host->af == AF_UNSPEC) {
				host->af = af;
				host->ip6addr = ip6h->ip6_src;
			}

			af = AF_UNSPEC;
			break;
		default:
			quit = 1;
		}

		offset += hdrsiz;
	}
}

void
analyzer_close(struct analyzer *a)
{
	int	 i;

	if (a == NULL)
		return;

	for (i = 0; i < a->host_max; i++) {
		if (a->host[i].src == -1)
			break;

		dest_list_destroy(&a->host[i].dest_list);
	}

	free(a->host);
	free(a);
}

uint64_t
print_dest_list(int fd, struct dest_list *dl, int af, int tab, const char *pfx)
{
	struct dest	*dest = NULL;
	char		 str[PRINTSIZ];
	char		 addr[32];
	const char	*npfx = pfx;
	int		 i, n = 0, len, ntab = tab;
	uint64_t	 total = 0, ntotal;

	len = sizeof(str);

	TAILQ_FOREACH(dest, dl, entry) {
		if (dest->count == 0)
			continue;

		if (af == dest->af) {
			n = 0;
			memset(str, 0, len);
			memset(addr, 0, sizeof(addr));
			n += snprintf(str + n, len - n, "%s", npfx);
			for (i=0; i < tab; i++)
				n += snprintf(str + n, len - n, "    ");

			switch (dest->af) {
			case AF_PACKET:
				mac_ntop((u_int8_t *)dest->addr, addr, sizeof(addr));
				break;
			case AF_INET:
				ip_ntop((u_int32_t *)dest->addr, addr, sizeof(addr));
				ntab += 1;
				break;
			default:
				snprintf(addr, sizeof(addr), "unsupported");
				break;
			}

			n += snprintf(str + n, len - n, "\"%s\" : %lu", addr, dest->count);
			write(fd, str, n);
			total += dest->count;
			npfx = ",\n";
		}

		ntotal = print_dest_list(fd, &dest->next_hdr, af, ntab, npfx);
		if (ntotal != 0)
			npfx = ",\n";
		total += ntotal;
	}

	return total;
}

void
analyzer_dump(struct analyzer *a, int fd)
{
	int		 i, n = 0, len;
	char		 str[PRINTSIZ];
	char		 addr[32];
	uint64_t	 total = 0;
	char		*comma = "";

	len = sizeof(str);
	n = 0;
	memset(str, 0, len);

	n += snprintf(str + n, len - n, "{\n");
	n += snprintf(str + n, len - n,
	    "    \"interface\" : \"%s\"\n" , a->ifname);
	n += snprintf(str + n, len - n,
	    "    \"flows\" : [");
	write(fd, str, n);
	n = 0;
	memset(str, 0, len);

	for (i = 0; i < a->host_max; i++) {
		if (a->host[i].src == -1)
			break;
		if (dest_list_empty(&a->host[i].dest_list))
			break;

		n += snprintf(str + n, len - n,
		    "%s\n"
		    "        {\n", comma);

		memset(addr, 0, sizeof(addr));
		mac_ntop(a->host[i].macaddr, addr, sizeof(addr));
		n += snprintf(str + n, len - n,
		    "            \"src_mac\": \"%s\"\n",
		    addr);

		if (a->host[i].af == AF_INET) {
			memset(addr, 0, sizeof(addr));
			ip_ntop(&a->host[i].ipaddr, addr, sizeof(addr));
			n += snprintf(str + n, len - n,
			    "            \"src_ip\" : \"%s\"\n",
			    addr);
		}
		n += snprintf(str + n, len - n,
		    "            \"dst\"    : [\n");
		write(fd, str, n);
		n = 0;
		memset(str, 0, sizeof(str));

		total += print_dest_list(fd, &a->host[i].dest_list, AF_INET,
		    4, "");
		n += snprintf(str + n, len - n,
		    "\n            ]\n");
		n += snprintf(str + n, len - n, "\n        }");
		write(fd, str, n);
		n = 0;
		memset(str, 0, sizeof(str));
		comma = ",";
	}
	n += snprintf(str + n, len - n, "\n    ]\n");
	n += snprintf(str + n, len - n, "    \"total_dst\" : %lu\n", total);
	n += snprintf(str + n, len - n, "}\n");
	write(fd, str, n);
}

void
clear_dest_list(struct dest_list *dl)
{
	struct dest	*dest = NULL;

	TAILQ_FOREACH(dest, dl, entry) {
		if (dest->count == 0)
			continue;

		dest->count = 0;
		clear_dest_list(&dest->next_hdr);
	}

}

void
analyzer_clear(struct analyzer *a)
{
	int		 i;

	for (i = 0; i < a->host_max; i++) {
		if (a->host[i].src == -1)
			break;

		clear_dest_list(&a->host[i].dest_list);
	}
}
