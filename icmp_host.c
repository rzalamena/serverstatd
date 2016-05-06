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

#include <stdlib.h>

#include "serverstatd.h"

/* Log address */
void
log_sa(struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char buf[128];

	switch (sa->sa_family) {
	case AF_INET:
		sin = satosin(sa);
		if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
			log_debug("# AF_INET: %s:%d", buf, ntohs(sin->sin_port));
		else
			log_debug("# AF_INET: invalid:%d", ntohs(sin->sin_port));
		break;

	case AF_INET6:
		sin6 = satosin6(sa);
		if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)))
			log_debug("# AF_INET6: %s:%d", buf, ntohs(sin6->sin6_port));
		else
			log_debug("# AF_INET6: invalid:%d", ntohs(sin6->sin6_port));
		break;

	default:
		log_debug("# %d: unknown", sa->sa_family);
	}
}

/* Get address length. */
socklen_t
slen_sa(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (sizeof(struct sockaddr_in));
	case AF_INET6:
		return (sizeof(struct sockaddr_in6));
	default:
		return (sizeof(struct sockaddr_storage));
	}
}

/* New icmp host */
struct icmp_host *
new_ih(uint16_t id)
{
	struct icmp_host *ih;

	if ((ih = calloc(1, sizeof(*ih))) == NULL) {
		log_warn("%s", __FUNCTION__);
		return (NULL);
	}

	ih->ih_id = id;
	return (ih);
}

/* Lookup ICMP host. */
struct icmp_host *
find_ih(uint16_t id)
{
	struct icmp_host *ih;

	TAILQ_FOREACH(ih, &sc.sc_ihlist, ih_entry) {
		if (ih->ih_id != id)
			continue;

		return (ih);
	}

	return (NULL);
}

/* Generate ICMP packet. */
struct icmp_packet *
new_ip(struct icmp_host *ih, struct proc_ctx *pc)
{
	struct icmp_packet *ip;
	struct icmp *icmp;
	char *ptr;

	if ((ip = calloc(1, sizeof(*ip))) == NULL) {
		log_warn("%s", __FUNCTION__);
		return (NULL);
	}

	TAILQ_INSERT_HEAD(&ih->ih_iplist, ip, ip_entry);
	ih->ih_ipcount++;

	ip->ip_seq = ih->ih_seq++;
	event_base_gettimeofday_cached(pc->pc_eb, &ip->ip_tv);

	ptr = ip->ip_buf;
	icmp = (struct icmp *) ptr;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = htons(ip->ip_seq);
	icmp->icmp_id = ih->ih_id;

	/* TODO fill packet. */

	icmp->icmp_cksum = in_cksum((uint16_t *) icmp, sizeof(ip->ip_buf));

	return (ip);
}

/* Find ICMP packet. */
struct icmp_packet *
find_ip(struct icmp_host *ih, uint16_t seq)
{
	struct icmp_packet *ip;

	TAILQ_FOREACH(ip, &ih->ih_iplist, ip_entry) {
		if (ip->ip_seq != seq)
			continue;

		return (ip);
	}

	return (NULL);
}

/* Remove ICMP packet. */
void
free_ip(struct icmp_host *ih, struct icmp_packet *ip)
{
	ih->ih_ipcount--;
	TAILQ_REMOVE(&ih->ih_iplist, ip, ip_entry);
	free(ip);
}

/* Reschedule packet timeout */
void
reschedule_icmp_send(struct icmp_host *ih)
{
	/* Default timeout to receive ICMP packet */
	static struct timeval deftimeout = { 10, 0 };
	static struct timeval defdelaytimeout = { 60, 0 };

	if (ih->ih_ihs == IHS_UP)
		evtimer_add(ih->ih_to, &deftimeout);
	else /* Host went down, increase the timeout with a delay. */
		evtimer_add(ih->ih_to, &defdelaytimeout);
}

/*
 * Shamelessly stolen from ping.c from OpenBSD.
 *
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
int
in_cksum(const uint16_t *addr, int len)
{
	int nleft = len;
	const uint16_t *w = addr;
	int sum = 0;
	uint16_t answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *) w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/* Register ICMP host to database. */
int
register_icmp_host(struct icmp_host *ih)
{
	struct sqlite3_stmt *ss;

	/* If it exists, just quit. */
	if (icmp_host_db_id(ih->ih_name))
		return (0);

	ss = db_prepare("INSERT INTO icmp_hosts(name, address) VALUES (?, ?);");
	if (ss == NULL) {
		log_warnx("%s: failed to prepare ICMP host registration",
		    __FUNCTION__);
		return (-1);
	}

	if (db_bindf(ss, "%s%s",
	    ih->ih_name, strlen(ih->ih_name),
	    ih->ih_address, strlen(ih->ih_address))) {
		db_finalize(&ss);
		log_warnx("%s: failed to bind values", __FUNCTION__);
		return (-1);
	}

	if (db_run(ss) != SQLITE_OK) {
		db_finalize(&ss);
		log_warnx("%s: failed to save", __FUNCTION__);
		return (-1);
	}

	db_finalize(&ss);
	return (0);
}

/* Find ICMP host row id */
static uint32_t
icmp_host_db_id(const char *name)
{
	struct sqlite3_stmt *ss;
	uint32_t dbid;

	ss = db_prepare("SELECT id FROM icmp_hosts WHERE name = ?;");
	if (ss == NULL)
		return (0);

	if (db_bindf(ss, "%s", name, strlen(name))) {
		log_warnx("%s: failed to bind query", __FUNCTION__);
		return (0);
	}

	if (db_run(ss) != SQLITE_ROW) {
		db_finalize(&ss);
		log_warnx("%s: failed to find '%s'", __FUNCTION__, name);
		return (0);
	}

	if (db_loadf(ss, "%i", &dbid)) {
		db_finalize(&ss);
		log_warnx("%s: failed to load result", __FUNCTION__);
		return (0);
	}

	db_finalize(&ss);
	return (dbid);
}

/* Log ICMP host events to the database. */
void
log_icmp_host_event(struct icmp_host *ih, enum icmp_host_status ihs)
{
	struct sqlite3_stmt *ss;
	uint32_t dbid;

	switch (ihs) {
	case IHS_UP:
		log_info("Host %s (%s) is now online",
		    ih->ih_name, ih->ih_address);
		break;
	case IHS_DOWN:
		log_info("Host %s (%s) is now offline",
		    ih->ih_name, ih->ih_address);
		break;
	default:
		log_warnx("Invalid ICMP host event");
		return;
	}

	dbid = icmp_host_db_id(ih->ih_name);

	ss = db_prepare("INSERT INTO icmp_host_events (icmp_host_id, event) VALUES (?, ?);");
	if (ss == NULL)
		log_warnx("# Failed to log host event");

	db_bindf(ss, "%i%i", dbid, ihs);
	if (db_run(ss) != SQLITE_OK)
		log_warnx("%s: failed to log event", __FUNCTION__);

	db_finalize(&ss);
}
