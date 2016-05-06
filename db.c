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

#include <stdarg.h>
#include <string.h>

#include "serverstatd.h"

static struct sqlite3 *dbp;

/*
 * Initialize the database in path.
 *
 * It's possible to use in memory database with ':memory:' path.
 */
int
db_init(const char *path)
{
	if (dbp)
		return (-1);

	if (sqlite3_open_v2(path, &dbp,
	    (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE), NULL) != SQLITE_OK) {
		if (dbp == NULL) {
			log_warnx("Failed to open dabatase '%s'", path);
			return (-1);
		}

		log_warnx("Failed to open database '%s': %s", path,
		    sqlite3_errmsg(dbp));
		if (sqlite3_close_v2(dbp) != SQLITE_OK)
			fatalx("Failed to terminate database");
		dbp = NULL;
		return (-1);
	}
	return (0);
}

/* Closes the database if open. */
int
db_close(void)
{
	if (dbp == NULL)
		return (0);

	if (sqlite3_close_v2(dbp) != SQLITE_OK) {
		log_warnx("Failed to terminate database");
		return (-1);
	}
	return (0);
}

/* Helper function to handle formating. */
static int
db_vbindf(struct sqlite3_stmt *ss, const char *fmt, va_list vl)
{
	const char *sptr = fmt;
	int column = 1;
	const char *str;
	void *blob;
	uint64_t uinteger64;
	uint32_t uinteger;
	int vlen;

	while (*sptr) {
		if (*sptr != '%') {
			sptr++;
			continue;
		}
		if (sptr++ && *sptr == 0)
			break;

		switch (*sptr) {
		case 'i':
			uinteger = va_arg(vl, uint32_t);
			if (sqlite3_bind_int(ss, column++, uinteger)
			    != SQLITE_OK)
				return (-1);
			break;
		case 'd':
			uinteger64 = va_arg(vl, uint64_t);
			if (sqlite3_bind_int64(ss, column++, uinteger)
			    != SQLITE_OK)
				return (-1);
			break;
		case 's':
			str = va_arg(vl, const char *);
			vlen = va_arg(vl, int);
			if (sqlite3_bind_text(ss, column++, str, vlen,
			    SQLITE_STATIC) != SQLITE_OK)
				return (-1);
			break;
		case 'b':
			blob = va_arg(vl, void *);
			vlen = va_arg(vl, int);
			if (sqlite3_bind_blob(ss, column++, blob, vlen,
			    SQLITE_STATIC) != SQLITE_OK)
				return (-1);
			break;
		case 'n':
			if (sqlite3_bind_null(ss, column++) != SQLITE_OK)
				return (-1);
			break;
		default:
			log_warnx("%s: invalid format '%c'", *sptr);
			return (-1);
		}
	}

	return (0);
}

/*
 * Binds values using format to the database query.
 *
 * Might be used to bind variables to a query, insert or update.
 */
int
db_bindf(struct sqlite3_stmt *ss, const char *fmt, ...)
{
	va_list vl;
	int result;

	va_start(vl, fmt);
	result = db_vbindf(ss, fmt, vl);
	va_end(vl);

	return (result);
}

/* Prepares an statement to the database with the statement length. */
struct sqlite3_stmt *
db_prepare_len(const char *stmt, int stmtlen)
{
	struct sqlite3_stmt *ss;
	int c;

	c = sqlite3_prepare_v2(dbp, stmt, stmtlen, &ss, NULL);
	if (ss == NULL) {
		log_debug("Failed to prepare (%d:%s) '%s'",
		    c, sqlite3_errmsg(dbp), stmt);
		return (NULL);
	}
	return (ss);
}

/* Prepares an statement to the database. */
struct sqlite3_stmt *
db_prepare(const char *stmt)
{
	return (db_prepare_len(stmt, strlen(stmt)));
}

/* Run a prepared statement. */
int
db_run(struct sqlite3_stmt *ss)
{
	int result;

	result = sqlite3_step(ss);
	switch (result) {
	case SQLITE_BUSY:
		/* TODO handle busy database. */
		break;

	case SQLITE_OK:
	/*
	 * SQLITE_DONE just causes confusion since it means the query went OK,
	 * but it has a different value.
	 */
	case SQLITE_DONE:
		result = SQLITE_OK;
		break;

	case SQLITE_ROW:
		/* NOTHING */
		/* It is expected to receive SQLITE_ROW on search queries. */
		break;

	default:
		log_debug("%s: step failed (%d:%s)",
		    __FUNCTION__, result, sqlite3_errstr(result));
	}

	return (result);
}

/* Helper function to load format to variables. */
static int
db_vloadf(struct sqlite3_stmt *ss, const char *fmt, va_list vl)
{
	const char *sptr = fmt;
	int column = 0;
	char *str;
	const unsigned char *txt;
	void *blob;
	const void *blobsrc;
	uint64_t *uinteger64;
	uint32_t *uinteger;
	int vlen;
	int dlen;
	int columncount;

	columncount = sqlite3_column_count(ss);
	if (columncount == 0)
		return (-1);

	while (*sptr) {
		if (*sptr != '%') {
			sptr++;
			continue;
		}
		if (sptr++ && *sptr == 0)
			break;

		switch (*sptr) {
		case 'i':
			uinteger = va_arg(vl, uint32_t *);
			*uinteger = sqlite3_column_int(ss, column++);
			break;
		case 'd':
			uinteger64 = va_arg(vl, uint64_t *);
			*uinteger64 = sqlite3_column_int64(ss, column++);
			break;
		case 's':
			str = va_arg(vl, char *);
			vlen = va_arg(vl, int);
			dlen = sqlite3_column_bytes(ss, column);
			txt = sqlite3_column_text(ss, column++);
			strlcpy(str, (const char *) txt, MIN(vlen, dlen));
			break;
		case 'b':
			blob = va_arg(vl, void *);
			vlen = va_arg(vl, int);
			dlen = sqlite3_column_bytes(ss, column);
			blobsrc = sqlite3_column_blob(ss, column++);
			memcpy(blob, blobsrc, MIN(vlen, dlen));
			break;
		default:
			log_warnx("%s: invalid format '%c'", *sptr);
			return (-1);
		}
	}

	return (0);
}

/* Function to load format from database row. */
int
db_loadf(struct sqlite3_stmt *ss, const char *fmt, ...)
{
	va_list vl;
	int result;

	va_start(vl, fmt);
	result = db_vloadf(ss, fmt, vl);
	va_end(vl);

	return (result);
}

/* Finalize query and return memory. */
void
db_finalize(struct sqlite3_stmt **ss)
{
	sqlite3_finalize(*ss);
	*ss = NULL;
}

/* Prepare and execute the statement. */
int
db_execute_len(const char *stmt, size_t stmtlen)
{
	struct sqlite3_stmt *ss;

	ss = db_prepare_len(stmt, stmtlen);
	if (ss == NULL)
		return (-1);

	if (db_run(ss) != SQLITE_OK) {
		db_finalize(&ss);
		return (-1);
	}

	db_finalize(&ss);
	return (0);
}

/* Prepare and execute statement without specifying length. */
int
db_execute(const char *stmt)
{
	return (db_execute_len(stmt, strlen(stmt)));
}
