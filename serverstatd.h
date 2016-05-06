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

#ifndef _SERVERSTATD_H_
#define _SERVERSTATD_H_

#include <compat.h>

#include <event2/event.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <imsg.h>

#include <errno.h>
#include <string.h>

#include <sqlite3.h>

#include "icmp_host.h"

#ifndef MIN
#define MIN(x, y) \
	(((x) > (y)) ? (y) : (x))
#endif /* MIN */

#define NOF(total, ssize) \
	((total) / (ssize))

struct proc_ctx;
typedef void (*handler_func)(struct proc_ctx *);

struct proc_ctx {
	const char *pc_name;
	handler_func pc_func;
	pid_t pc_pid;
	int pc_sp[2];
	struct imsgbuf pc_ibuf;
	struct event *pc_ev;
	struct event *pc_evout;
	struct event_base *pc_eb;
	void *pc_data;
};

enum proc_msg_type {
	IMSG_SOCKET_RAW,
	IMSG_HOST_UP,
	IMSG_HOST_DOWN,
};

struct serverstatd_conf {
	char *sc_user;
	char *sc_chroot;
	TAILQ_HEAD(, icmp_host) sc_ihlist;
};

extern struct serverstatd_conf sc;

/* serverstatd.c */
void pc_add(struct event_base *, struct proc_ctx *, int, event_callback_fn);
int compose_to_child(struct proc_ctx *, uint32_t, int, const void *, uint16_t);
int compose_to_father(struct proc_ctx *, uint32_t, const void *, uint16_t);

/* db.c */
int db_init(const char *);
int db_close(void);
struct sqlite3_stmt *db_prepare(const char *);
struct sqlite3_stmt *db_prepare_len(const char *, int);
int db_bindf(struct sqlite3_stmt *, const char *, ...);
int db_run(struct sqlite3_stmt *);
int db_loadf(struct sqlite3_stmt *, const char *, ...);
void db_finalize(struct sqlite3_stmt **);
int db_execute_len(const char *, size_t);
int db_execute(const char *);

/* parse.y */
int parse_config(const char *, struct serverstatd_conf *);

/* icmp.c */
int icmp_socket(void);
void icmp_handler(struct proc_ctx *);

/* log.c */
void log_init(int);
void log_verbose(int);

void log_warn(const char *, ...);
void log_warnx(const char *, ...);
void log_info(const char *, ...);
void log_debug(const char *, ...);
void fatal(const char *, ...);
void fatalx(const char *, ...);

#endif /* _SERVERSTATD_H_ */
