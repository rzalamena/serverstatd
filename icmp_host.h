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

#ifndef _ICMP_HOST_H_
#define _ICMP_HOST_H_

#include <arpa/inet.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Forward structure declaration */
struct proc_ctx;

/*
 * Helper functions:
 *
 * This is not a macro because it enables compiler to check types.
 */
static inline struct sockaddr *
sstosa(struct sockaddr_storage *ss)
{
	return ((struct sockaddr *) ss);
}

static inline struct sockaddr_in *
sstosin(struct sockaddr_storage *ss)
{
	return ((struct sockaddr_in *) ss);
}

static inline struct sockaddr_in6 *
sstosin6(struct sockaddr_storage *ss)
{
	return ((struct sockaddr_in6 *) ss);
}

static inline struct sockaddr_in *
satosin(struct sockaddr *sa)
{
	return ((struct sockaddr_in *) sa);
}

static inline struct sockaddr_in6 *
satosin6(struct sockaddr *sa)
{
	return ((struct sockaddr_in6 *) sa);
}

socklen_t slen_sa(struct sockaddr *);

/* Debug functions */
void log_sa(struct sockaddr *);

/* ICMP packet */
struct icmp_packet {
	TAILQ_ENTRY(icmp_packet) ip_entry;
	struct timeval ip_tv;
	uint16_t ip_seq;
	char ip_buf[1536];
};

/* ICMP host item */
#define IH_DEF_RETRYCOUNT (3)

enum icmp_host_status {
	IHS_DOWM = 0,
	IHS_UP = 1,
};

struct icmp_host {
	TAILQ_ENTRY(icmp_host) ih_entry;
	TAILQ_HEAD(, icmp_packet) ih_iplist;

	/* Process pointer */
	struct proc_ctx *ih_pc;

	/* Probe configuration */
	char *ih_name;
	char *ih_address;
	struct sockaddr_storage ih_ss;

	/* Current probe status */
	uint16_t ih_id;
	uint16_t ih_seq;
	unsigned ih_retrycount;
	unsigned ih_ipcount;
	enum icmp_host_status ih_ihs;

	struct timeval ih_ltv; /* last event time */
	struct event *ih_to; /* event registration */
};

/* icmp_host.c */
struct icmp_host *new_ih(uint16_t);
struct icmp_host *find_ih(uint16_t);
int in_cksum(const uint16_t *, int);

struct icmp_packet *new_ip(struct icmp_host *, struct proc_ctx *);
struct icmp_packet *find_ip(struct icmp_host *, uint16_t);
void free_ip(struct icmp_host *, struct icmp_packet *);

void reschedule_icmp_send(struct icmp_host *);

#endif /* _ICMP_HOST_H_ */
