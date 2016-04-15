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

#ifdef LINUX_SUPPORT
/* Needed by setresgid() and setresuid() */
#define _GNU_SOURCE
#endif /* LINUX_SUPPORT */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <grp.h>

#ifdef MACOSX_SUPPORT
#include <uuid/uuid.h>
#endif /* MACOSX_SUPPORT */

#include "serverstatd.h"

/* Global configuration structure shared between children. */
struct serverstatd_conf sc;

/* Child worker process declaration */
struct proc_ctx pcs[1] = {
	{
		.pc_name = "icmp probe",
		.pc_func = icmp_handler,
		.pc_pid = 0,
		.pc_sp = { -1, -1 },
		.pc_ev = NULL,
		.pc_evout = NULL,
	},
};

/* Main process signal handlers */
static void
main_term_handler(evutil_socket_t s, short ev, void *bula)
{
	int n;
	pid_t pid;

	log_info("%s: received signal %d", __FUNCTION__, s);

	for (n = 0; n < NOF(sizeof(pcs), sizeof(pcs[0])); n++) {
		if (pcs[n].pc_pid == 0)
			continue;

		kill(pcs[n].pc_pid, SIGTERM);
	}

	do {
		if ((pid = wait(NULL)) == -1 &&
		    errno != EINTR && errno != ECHILD)
			fatal("wait");
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	exit(0);
}

static void
main_hup_handler(evutil_socket_t s, short ev, void *bula)
{
	log_info("%s: received signal %s", __FUNCTION__, s);
}

/* Main process dispatcher */
static void
main_dispatcher(evutil_socket_t sd, short ev, void *arg)
{
	struct proc_ctx *pc = arg;
	struct icmp_host *ih;
	struct imsg imsg;
	int n;
	int sraw;

	if (imsg_read(&pc->pc_ibuf) == -1 && errno != EAGAIN)
		fatal("%s: imsg_read", __FUNCTION__);

	while (1) {
		if ((n = imsg_get(&pc->pc_ibuf, &imsg)) == -1)
			break;
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_SOCKET_RAW:
			log_debug("%s: new icmp socket", __FUNCTION__);
			sraw = icmp_socket();
			compose_to_child(&pcs[0], IMSG_SOCKET_RAW, sraw, NULL, 0);
			break;
		case IMSG_HOST_UP:
			ih = imsg.data;
			log_info("Host %s (%s) is now online",
			    ih->ih_name, ih->ih_address);
			break;
		case IMSG_HOST_DOWN:
			ih = imsg.data;
			log_info("Host %s (%s) is now offline",
			    ih->ih_name, ih->ih_address);
			break;

		default:
			log_debug("unhandled message type: %#08x",
			    imsg.hdr.type);
			break;
		}
	}
}

/* Generic message sender dispatcher. */
static void
send_dispatcher(evutil_socket_t sd, short ev, void *arg)
{
	struct proc_ctx *pc = arg;

	if (imsg_flush(&pc->pc_ibuf) == -1)
		log_warn("%s: imsg_flush", __FUNCTION__);

	/* Reschedule if there is more writes pending. */
	if (pc->pc_ibuf.w.queued)
		event_add(pc->pc_evout, NULL);
}

/* Send a message from father to child. */
int
compose_to_child(struct proc_ctx *pc, uint32_t type, int fd, const void *data,
    uint16_t datalen)
{
	if (imsg_compose(&pc->pc_ibuf, type, 0, 0, fd, data, datalen) != 1)
		return (-1);

	event_add(pc->pc_evout, NULL);

	return (0);
}

/* Send message from child to father. */
int
compose_to_father(struct proc_ctx *pc, uint32_t type, const void *data,
    uint16_t datalen)
{
	if (imsg_compose(&pc->pc_ibuf, type, 0, 0, -1, data, datalen) != 1)
		return (-1);

	event_add(pc->pc_evout, NULL);

	return (0);
}

/* Initialize the pipe with a handler. */
void
pc_add(struct event_base *eb, struct proc_ctx *pc, int fd, event_callback_fn func)
{
	pc->pc_eb = eb;

	/* Attach read handler. */
	pc->pc_ev = event_new(eb, fd, EV_READ | EV_PERSIST, func, pc);
	event_add(pc->pc_ev, NULL);

	/* Attach write handler. */
	pc->pc_evout = event_new(eb, fd, EV_WRITE, send_dispatcher, pc);

	/* Initiate imsg API. */
	imsg_init(&pc->pc_ibuf, fd);
}

/* Generic function to spawn child processes. */
static int
launch_proc(struct proc_ctx *pc)
{
	struct passwd *pw;
	pid_t pid;

#ifdef MACOSX_SUPPORT
	if (socketpair(PF_LOCAL, SOCK_STREAM, AF_UNSPEC, pc->pc_sp) == -1 ||
	    evutil_make_socket_closeonexec(pc->pc_sp[0]) == -1 ||
	    evutil_make_socket_closeonexec(pc->pc_sp[1]) == -1 ||
	    evutil_make_socket_nonblocking(pc->pc_sp[0]) == -1 ||
	    evutil_make_socket_nonblocking(pc->pc_sp[1]) == -1)
#else
	if (socketpair(PF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    AF_UNSPEC, pc->pc_sp) == -1)
#endif /* MACOSX_SUPPORT */
		fatal("%s: socketpair", pc->pc_name);

	switch ((pid = fork())) {
	case 0:
		break;

	case -1:
		log_warn("Failed to spawn %s", pc->pc_name);
	default:
		close(pc->pc_sp[1]);
		pc->pc_sp[1] = -1;
		return (pc->pc_pid = pid);
	}

	close(pc->pc_sp[0]);
	pc->pc_sp[0] = -1;

	/* Load user details to drop privileges. */
	if ((pw = getpwnam(sc.sc_user)) == NULL)
		fatal("failed to get user");

	/* Use user home as chroot, otherwise use definition. */
	if (sc.sc_chroot[0] == 0) {
		if (chroot(pw->pw_dir) != 0)
			fatal("chroot");
	} else {
		if (chroot(sc.sc_chroot) != 0)
			fatal("chroot");
	}

	/* Drop privileges. */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("failed to drop privileges");

	pc->pc_func(pc);

	_exit(0);
}

static void
usage(void)
{
	extern const char *__progname;
	fprintf(stderr, "%s: [-dfv]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *cfgfile = "/tmp/serverstatd.conf";
	int foreground = 0;
	int verbose = 0;
	int c;
	struct event_base *eb;
	struct event *evsig_hup, *evsig_term, *evsig_int, *evsig_chld;

	while ((c = getopt(argc, argv, "df:v")) != -1) {
		switch (c) {
		case 'd':
			foreground = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'f':
			cfgfile = strdup(optarg);
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	/* Check for root privileges. */
	if (geteuid())
		errx(1, "need root privileges");

	/* Initialize log operation. */
	log_init(foreground);
	log_verbose(verbose);

	/* Deal with configuration files. */
	if (parse_config(cfgfile, &sc) != 0)
		errx(1, "failed to read configuration");

	/* Check the chroot dir. */
	if (access(sc.sc_chroot, F_OK) != 0)
		err(1, "could not open chroot directory");

	/* Check for serverstatd user. */
	if (getpwnam(sc.sc_user) == NULL)
		errx(1, "unknown user %s", sc.sc_user);

#ifndef MACOSX_SUPPORT
	if (foreground == 0)
		if (daemon(1, 0) != 0)
			fatal("daemonize");
#endif /* MACOSX_SUPPORT */

	/* Launch children processes. */
	launch_proc(&pcs[0]);

	/* Register all events then go to main loop. */
	eb = event_base_new();

	signal(SIGPIPE, SIG_IGN);
	evsig_chld = evsignal_new(eb, SIGCHLD, main_term_handler, NULL);
	evsig_term = evsignal_new(eb, SIGTERM, main_term_handler, NULL);
	evsig_int = evsignal_new(eb, SIGINT, main_term_handler, NULL);
	evsig_hup = evsignal_new(eb, SIGHUP, main_hup_handler, NULL);
	evsignal_add(evsig_chld, NULL);
	evsignal_add(evsig_term, NULL);
	evsignal_add(evsig_int, NULL);
	evsignal_add(evsig_hup, NULL);

	pc_add(eb, &pcs[0], pcs[0].pc_sp[0], main_dispatcher);

	log_info("started");

	event_base_dispatch(eb);
	/* NOTREACHED */

	event_base_free(eb);

	return (0);
}
