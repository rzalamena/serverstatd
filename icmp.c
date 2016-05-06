/*
 * Copyright (c) 2016 Rafael Zalamena <rzalamena@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "serverstatd.h"

/* ICMP probe main data structure */
struct icmp_probe_data {
	int ipd_sd; /* Raw socket obtained with icmp_socket() */
	struct event *ipd_sdev;
};

/* ICMP probe signal handler */
static void
icmp_handle_term(evutil_socket_t s, short ev, void *bula)
{
	log_debug("icmp probe received signal %d", s);

	_exit(EXIT_SUCCESS);
}

/* Create ICMP raw socket. */
int
icmp_socket(void)
{
	 int s;

	 if ((s = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		 fatal("socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)");

	return (s);
}

/* Send ICMP packet. */
int
icmp_send(int sd, struct icmp_host *ih, struct proc_ctx *pc)
{
	struct sockaddr *sa;
	struct icmp_packet *ip;
	ssize_t sent;

	if ((ip = new_ip(ih, pc)) == NULL)
		return (-1);

	sa = sstosa(&ih->ih_ss);
	sent = sendto(sd, ip->ip_buf, 512, 0, sa, slen_sa(sa));
	if (sent <= 0) {
		log_warn("%s sendto failed", __FUNCTION__);
		return (-1);
	}

	reschedule_icmp_send(ih);

	log_debug("Sent %s (%s) ICMP(id %d, seq %d) packet",
	    ih->ih_name, ih->ih_address, ih->ih_id, ip->ip_seq);

	return (0);
}

/* Helper function to hide ping receive and parse. */
static int
icmp_parse(int sd, char *p, size_t plen, struct sockaddr_storage *ss,
    struct ip **ip, struct icmp **icmp)
{
	size_t iplen;
	size_t bytesread;
	struct msghdr msg;
	struct iovec iov[1];
	struct sockaddr *sa;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(1024)];
	} cmsgbuf;

	msg.msg_name = ss;
	msg.msg_namelen = sizeof(*ss);
	iov[0].iov_base = p;
	iov[0].iov_len = plen;
	msg.msg_iov = iov;
	msg.msg_iovlen = NOF(sizeof(iov), sizeof(iov[0]));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	if ((bytesread = recvmsg(sd, &msg, 0)) == -1)
		fatal("recvmsg failed");

	sa = msg.msg_name;
	if (sa == NULL ||
	    msg.msg_namelen < sizeof(struct sockaddr_in) ||
	    (sa->sa_family != AF_INET /* && sa->sa_family != AF_INET6 */)) {
		log_debug("unsupported family %d", sa->sa_family);
		return (-1);
	}

	/* TODO IPv6 */
	*ip = (struct ip *) p;
	iplen = (*ip)->ip_hl << 2;
	if (bytesread < (iplen + ICMP_MINLEN)) {
		log_debug("packet too small");
		return (-1);
	}

	*icmp = (struct icmp *) (p + iplen);

	return (0);
}

/* Raw socket handler. */
static void
icmp_raw_socket_handler(evutil_socket_t sd, short ev, void *arg)
{
	struct proc_ctx *pc = arg;
	struct icmp_probe_data *ipd = pc->pc_data;
	struct ip *ip;
	struct icmp *icmp;
	struct icmp_host *ih;
	struct icmp_packet *ipkt;
	struct sockaddr_storage ss;
	char buf[1536];

	if (icmp_parse(ipd->ipd_sd, buf, sizeof(buf), &ss, &ip, &icmp))
		return;

	if ((ih = find_ih(icmp->icmp_id)) == NULL) {
		log_debug("received ICMP packet, but it's not for us");
		return;
	}

	if (icmp->icmp_type != ICMP_ECHOREPLY) {
		/* TODO handle unreachable */
		log_debug("received ICMP type %d", icmp->icmp_type);
		return;
	}

	icmp->icmp_seq = ntohs(icmp->icmp_seq);
	if ((ipkt = find_ip(ih, icmp->icmp_seq)) == NULL) {
		log_debug("received out-of-sequence packet: %d",
		    icmp->icmp_seq);
		return;
	}

	if (ih->ih_ihs == IHS_DOWN) {
		log_debug("%s (%s) is up", ih->ih_name, ih->ih_address);
		ih->ih_ihs = IHS_UP;
		compose_to_father(pc, IMSG_HOST_UP, ih, sizeof(*ih));
	}

	ih->ih_retrycount = IH_DEF_RETRYCOUNT;

	/* Reschedule ICMP packet. */
	reschedule_icmp_send(ih);

	free_ip(ih, ipkt);
}

/* Main event dispatcher. */
static void
icmp_main_dispatcher(evutil_socket_t sd, short ev, void *arg)
{
	struct proc_ctx *pc = arg;
	struct icmp_probe_data *ipd = pc->pc_data;
	struct icmp_host *ih;
	struct imsg imsg;
	int n;

	if (imsg_read(&pc->pc_ibuf) == -1 && errno != EAGAIN)
		fatal("%s: imsg_read", __FUNCTION__);

	while (1) {
		if ((n = imsg_get(&pc->pc_ibuf, &imsg)) == -1)
			break;
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_SOCKET_RAW:
			ipd->ipd_sd = imsg.fd;
			ipd->ipd_sdev = event_new(pc->pc_eb, ipd->ipd_sd,
			    EV_READ | EV_PERSIST, icmp_raw_socket_handler, pc);
			event_add(ipd->ipd_sdev, NULL);
			TAILQ_FOREACH(ih, &sc.sc_ihlist, ih_entry)
				icmp_send(ipd->ipd_sd, ih, pc);
			break;

		default:
			log_debug("unhandled message type: %#08x",
			    imsg.hdr.type);
			break;
		}
	}
}

/* Handle ICMP host timeouts. */
static void
ih_timeout(evutil_socket_t bula, short ev, void *arg)
{
	struct icmp_host *ih = arg;
	struct proc_ctx *pc = ih->ih_pc;
	struct icmp_probe_data *ipd = pc->pc_data;
	struct icmp_packet *ip, *ipn;

	if (ih->ih_ihs == IHS_UP &&
	    ih->ih_retrycount == 0) {
		log_debug("%s (%s) is down", ih->ih_name, ih->ih_address);
		ih->ih_ihs = IHS_DOWN;

		compose_to_father(pc, IMSG_HOST_DOWN, ih, sizeof(*ih));

		/* Don't bother expecting response from a down host. */
		TAILQ_FOREACH_SAFE(ip, &ih->ih_iplist, ip_entry, ipn)
			free_ip(ih, ip);

		/* Host just went down, reschedule it for later. */
		reschedule_icmp_send(ih);
		return;
	}

	if (ih->ih_retrycount)
		ih->ih_retrycount--;

	icmp_send(ipd->ipd_sd, ih, pc);
}

/* Initialize ICMP host. */
static int
init_ih(struct icmp_host *ih, struct proc_ctx *pc)
{
	/* TODO handle resolving DNS */
	if (inet_pton(AF_INET, ih->ih_address,
	    &sstosin(&ih->ih_ss)->sin_addr.s_addr) != 1) {
		if (inet_pton(AF_INET6, ih->ih_address,
		    &sstosin6(&ih->ih_ss)->sin6_addr) != 1) {
			fatal("unable to translate %s", ih->ih_address);
			TAILQ_REMOVE(&sc.sc_ihlist, ih, ih_entry);
			free(ih);
			return (-1);
		} else {
			ih->ih_ss.ss_family = AF_INET6;
#ifndef LINUX_SUPPORT
			/* Linux doesn't have *_len on sockaddr structures. */
			ih->ih_ss.ss_len = sizeof(struct sockaddr_in6);
#endif /* LINUX_SUPPORT */
		}
	} else {
		ih->ih_ss.ss_family = AF_INET;
#ifndef LINUX_SUPPORT
		/* Linux doesn't have *_len on sockaddr structures. */
		ih->ih_ss.ss_len = sizeof(struct sockaddr_in);
#endif /* LINUX_SUPPORT */
	}
	ih->ih_pc = pc;
	ih->ih_to = evtimer_new(pc->pc_eb, ih_timeout, ih);
	ih->ih_retrycount = IH_DEF_RETRYCOUNT;
	return (0);
}

/* Process start function. */
void
icmp_handler(struct proc_ctx *pc)
{
	struct event_base *eb = event_base_new();
	struct icmp_probe_data *ipd;
	struct icmp_host *ih, *ihn;
	struct event *evsig_term, *evsig_int;

	/* Initialize icmp probe private data. */
	if ((pc->pc_data = calloc(1, sizeof(*ipd))) == NULL)
		fatal("%s", __FUNCTION__);

	ipd = pc->pc_data;
	ipd->ipd_sd = -1;

	/* Install signal handlers */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	evsig_term = evsignal_new(eb, SIGTERM, icmp_handle_term, NULL);
	evsig_int = evsignal_new(eb, SIGINT, icmp_handle_term, NULL);
	evsignal_add(evsig_term, NULL);
	evsignal_add(evsig_int, NULL);

	/* Register main process handler */
	pc_add(eb, pc, pc->pc_sp[1], icmp_main_dispatcher);

	/* Initialize probes. */
	TAILQ_FOREACH_SAFE(ih, &sc.sc_ihlist, ih_entry, ihn) {
		if (init_ih(ih, pc))
			continue;

		log_debug("registered icmp probe %s (%s)",
		    ih->ih_name, ih->ih_address);
	}

	/* Ask for a raw socket. */
	compose_to_father(pc, IMSG_SOCKET_RAW, NULL, 0);

	event_base_dispatch(eb);
	/* NOTREACHED */
}
