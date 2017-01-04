/*
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * HTTP Public Key Pinning
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <wget.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/stat.h>
#include "private.h"

struct __wget_hpkp_db_st {
	wget_hashmap_t *
		entries;
	wget_thread_mutex_t
		mutex;
};

struct __wget_hpkp_st {
	const char *
		host;
	time_t
		created;
	time_t
		max_age;
	char
		include_subdomains;
	wget_vector_t *
		pins;
};

/*
 * TODO HPKP: include target port as well.
 */
static unsigned int G_GNUC_WGET_PURE __hash_hpkp_cb(const void *data)
{
	unsigned int hash = 1;
	const unsigned char *p;

	for (p = (unsigned char *) data; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

/*
 * TODO HPKP: include target port as well.
 */
static int __cmp_hpkp_cb(const void *h1, const void *h2)
{
	const char *H1 = h1, *H2 = h2;
	return strcmp(H1, H2);
}

/*
 * Callback for comparing two SPKI hashes. Should return 0 if they're equal.
 * Currently HPKP only supports SHA-256 hashing.
 * This gives us 256 bits == 32 bytes output.
 * So we test byte-for-byte 32 times.
 */
static int __cmp_pins_cb(const void *P1, const void *P2)
{
	const uint8_t *p1 = P1, *p2 = P2;
	uint8_t all_equal = 1;

	/* We're dealing with public values anyway, so we can speed up the comparison */
	for (int i = 0; i < 32 && all_equal; i++) {
		if (p1[i] != p2[i])
			all_equal = 0;
	}

	return (int) !all_equal;
}

static void __wget_hpkp_free(wget_hpkp_t *hpkp, char free_host)
{
	if (free_host)
		xfree(hpkp->host);
	wget_vector_clear(hpkp->pins);
	xfree(hpkp);
}

/*
 * This is a callback function to destroy an hpkp entry.
 * It will be invoked by the hash table.
 */
static void wget_hpkp_free(wget_hpkp_t *hpkp)
{
	if (hpkp) {
		/* No need to free hpkp->host. It's already been freed by the hash table. */
		__wget_hpkp_free(hpkp, 0);
	}
}

/*
 * TODO HPKP: wget_hpkp_new() should get an IRI rather than a string, and check by itself
 * whether it is HTTPS, not an IP literal, etc.
 *
 * This is also applicable to HSTS.
 */
static wget_hpkp_t *wget_hpkp_new(const char *host, time_t created, time_t max_age, int include_subdomains)
{
	wget_hpkp_t *hpkp = xcalloc(1, sizeof(wget_hpkp_t));

	hpkp->host = wget_strdup(host);
	hpkp->created = created;
	hpkp->max_age = max_age;
	hpkp->include_subdomains = include_subdomains;

	/*
	 * Currently HPKP only supports SHA-256 hashing.
	 * Should it support more hash functions in the future,
	 * we should modify the _cmp_pins function somehow.
	 *
	 * Also, we don't need a destructor. Default behavior is to xfree() the values,
	 * which is OK, since wget_hpkp_add_public_key_base64() allocates new copies.
	 */
	hpkp->pins = wget_vector_create(5, -2, __cmp_pins_cb);

	return hpkp;
}

wget_hpkp_db_t *wget_hpkp_db_init()
{
	wget_hpkp_db_t *hpkp_db = xcalloc(1, sizeof(wget_hpkp_db_t));

	hpkp_db->entries = wget_hashmap_create(16, -2,
			(unsigned int (*) (const void *)) __hash_hpkp_cb,
			__cmp_hpkp_cb);
	/*
	 * Keys are hosts: the hpkp->host field, which is strdup-ed in wget_hpkp_new(),
	 * so we have to free it. But the default key destructor is free(),
	 * so we don't have to set it ourselves.
	 *
	 * Values are wget_hpkp_t structures, so we have to destroy them manually.
	 * This is done in the wget_hpkp_free() function.
	 */
	wget_hashmap_set_value_destructor(hpkp_db->entries,
			(void (*) (void *)) wget_hpkp_free);

	wget_thread_mutex_init(&hpkp_db->mutex);

	return hpkp_db;
}

void wget_hpkp_db_free(wget_hpkp_db_t *hpkp_db)
{
	if (hpkp_db) {
		wget_thread_mutex_lock(&hpkp_db->mutex);
		wget_hashmap_free(&hpkp_db->entries);
		wget_thread_mutex_unlock(&hpkp_db->mutex);
	}
}

void wget_hpkp_db_deinit(wget_hpkp_db_t **hpkp_db)
{
	if (hpkp_db && *hpkp_db) {
		wget_hpkp_db_free(*hpkp_db);
		xfree(*hpkp_db);
	}
}

static int __wget_hpkp_contains_spki_cb(wget_hpkp_t *hpkp, const char *spki)
{
	return !wget_vector_contains(hpkp->pins, spki);
}

static int __wget_hpkp_compare_spkis(wget_hpkp_t *hpkp1, wget_hpkp_t *hpkp2)
{
	return wget_vector_browse(hpkp1->pins, (int (*) (void *, void *)) __wget_hpkp_contains_spki_cb, hpkp2);
}

static int __wget_hpkp_db_put_base64_spki(wget_hpkp_t *hpkp, const char *b64_pubkey)
{
	if (!hpkp || !hpkp->pins || !b64_pubkey)
		return -1;

	//size_t pubkey_len = wget_base64_get_decoded_length(strlen(b64_pubkey));
	char *pubkey = wget_base64_decode_alloc(b64_pubkey, strlen(b64_pubkey));

	if (!wget_vector_contains(hpkp->pins, pubkey)) {
		wget_vector_add_noalloc(hpkp->pins, pubkey);
		wget_debug_printf("Added public key pin '%s' for host '%s'\n", b64_pubkey, hpkp->host);
	} else {
		xfree(pubkey);
		wget_debug_printf("Public key pin '%s' already in list. Skipping.\n", b64_pubkey);
	}

	return 0;
}

/*
 * Return values:
 * 	WGET_HPKP_OK : new entry was created and added, or an existing entry was updated
 * 	WGET_HPKP_WAS_DELETED : entry was deleted (max_age == 0 || num_pins == 0)
 * 	WGET_HPKP_ENTRY_EXPIRED : entry is expired (created + max_age < cur_time)
 * 	WGET_HPKP_NOT_ENOUGH_PINS : not enough pins were in the list (there must be at least 2)
 * 	WGET_HPKP_ENTRY_EXISTS : excl was == 1 and an entry already existed for hpkp->host
 *
 * This function should be guaranteed to create a new entry if it does not exist, is not expired
 * and has more than two public key pinnings, or do nothing and return WGET_HPKP_ENTRY_EXISTS
 * if any of the conditions is not met.
 *
 * A negative value means the caller should free 'hpkp_new', it does not necessarily signal
 * an error condition. All the return values except WGET_HPKP_OK are negative.
 */
static int __wget_hpkp_db_add(wget_hpkp_db_t *hpkp_db, wget_hpkp_t *hpkp_new, char excl)
{
	wget_hpkp_t *hpkp = NULL;
	time_t curtime = time(NULL);
	int num_pins = 0, retval = WGET_HPKP_ERROR;

	if (curtime == -1)
		curtime = 0;

	/* Check whether entry is expired already */
	if ((hpkp_new->created + hpkp_new->max_age) < curtime)
		return WGET_HPKP_ENTRY_EXPIRED;

	num_pins = wget_vector_size(hpkp_new->pins);
	hpkp = wget_hashmap_get(hpkp_db->entries, hpkp_new->host);
	if (hpkp && excl)
		return WGET_HPKP_ENTRY_EXISTS;

	if (hpkp == NULL && hpkp_new->max_age != 0 && num_pins >= 2) {
		/* This entry is not a known pinned host, so we add it */
		wget_thread_mutex_lock(&hpkp_db->mutex);
		wget_hashmap_put_noalloc(hpkp_db->entries, hpkp_new->host, hpkp_new);
		wget_thread_mutex_unlock(&hpkp_db->mutex);
		retval = WGET_HPKP_OK;
	} else if (hpkp && hpkp_new->max_age != 0 && num_pins >= 2 &&
			hpkp->created < hpkp_new->created &&
			(hpkp->include_subdomains != hpkp_new->include_subdomains ||
			hpkp->max_age != hpkp_new->max_age ||
			__wget_hpkp_compare_spkis(hpkp, hpkp_new))) {
		wget_thread_mutex_lock(&hpkp_db->mutex);
		wget_hashmap_put_noalloc(hpkp_db->entries, hpkp_new->host, hpkp_new);
		wget_thread_mutex_unlock(&hpkp_db->mutex);
//		__wget_hpkp_free(hpkp, 0);
		retval = WGET_HPKP_OK;
	} else if (hpkp && (hpkp_new->max_age == 0 || num_pins == 0)) {
		/* A value of max-age == 0 or no SPKIs means delete the entry */
		wget_thread_mutex_lock(&hpkp_db->mutex);
		wget_hashmap_remove(hpkp_db->entries, hpkp->host);
		wget_thread_mutex_unlock(&hpkp_db->mutex);
//		__wget_hpkp_free(hpkp, 1);
		retval = WGET_HPKP_WAS_DELETED;
	} else if (num_pins < 2) {
		/* There must be at least two SPKIs (one active and one backup) */
		retval = WGET_HPKP_NOT_ENOUGH_PINS;
	}

	return retval;
}

int wget_hpkp_db_add(wget_hpkp_db_t *hpkp_db, const char *host, time_t max_age, char include_subdomains, wget_vector_t *b64_pins)
{
	int retval;
	time_t cur_time = time(NULL);
	wget_hpkp_t *hpkp;

	if (!hpkp_db || !hpkp_db->entries || !host || !b64_pins)
		return WGET_HPKP_ERROR;

	if (cur_time == -1)
		cur_time = 0;

	hpkp = wget_hpkp_new(host, cur_time, max_age, include_subdomains);
	wget_vector_browse(b64_pins, (int (*) (void *, void *)) __wget_hpkp_db_put_base64_spki, hpkp);

	retval = __wget_hpkp_db_add(hpkp_db, hpkp, 0);
	if (retval < 0)
		__wget_hpkp_free(hpkp, 1);

	return retval;
}

static int __vector_browse_cb(void *ctx, void *elem)
{
	FILE *fp = ctx;
	const char *hash = elem, *b64_hash;

	if (!hash)
		return -1;

	b64_hash = wget_base64_encode_alloc(hash, 32);
	/* As said before, only SHA-256 is supported for now */
	fprintf(fp, "sha-256\t%s\n", b64_hash);
	xfree(b64_hash);

	return 0;
}

struct browser_ctx {
	FILE *fp;
	unsigned int written_pins;
};

static int __hashtable_browse_cb(void *ctx, const void *key, void *value)
{
	struct browser_ctx *bctx = ctx;
	int retval = 0;
	FILE *fp = bctx->fp;
	const char *url = key;
	const wget_hpkp_t *hpkp = value;

	if (!hpkp->pins)
		return -1;

	unsigned int num_pins = wget_vector_size(hpkp->pins);
	if (num_pins > 0) {
		fprintf(fp, "%s\t%lu\t%lu\t%u\t%u\n",
				url,
				hpkp->created, hpkp->max_age,
				hpkp->include_subdomains,
				num_pins);

		if (wget_vector_browse(hpkp->pins, __vector_browse_cb, fp) == 0)
			bctx->written_pins += num_pins;
		else
			retval = -1;
	} else {
		retval = -1;
	}

	return retval;
}

int wget_hpkp_db_save(const char *filename, wget_hpkp_db_t *hpkp_db)
{
	struct stat st;
	struct browser_ctx bctx;

	if (!filename || !*filename || !hpkp_db || !hpkp_db->entries)
		return WGET_HPKP_ERROR;

	bctx.fp = NULL;
	bctx.written_pins = 0;

	if (wget_hashmap_size(hpkp_db->entries) == 0) {
		/* No entries. If the file exists, remove it. */
		if (stat(filename, &st) == 0)
			unlink(filename);
		goto end;
	}

	bctx.fp = fopen(filename, "w");
	if (!bctx.fp)
		return WGET_HPKP_ERROR_FILE_OPEN;

	fprintf(bctx.fp, "# HTTP Public Key Pinning database (RFC 7469)\n");
	fprintf(bctx.fp, "# Generated by wget2\n");
	fprintf(bctx.fp, "# MODIFY AT YOUR OWN RISK\n");

	wget_thread_mutex_lock(&hpkp_db->mutex);
	wget_hashmap_browse(hpkp_db->entries, __hashtable_browse_cb, &bctx);
	wget_thread_mutex_unlock(&hpkp_db->mutex);

	fclose(bctx.fp);

end:
	return bctx.written_pins;
}

enum hpkp_parse_state {
	PARSING_HOST,
	PARSING_PIN,
	ERROR_CONTINUE,
	ERROR
};

/* Narrow down what isspace() considers a space */
#ifdef isspace
#undef isspace
#endif
#define isspace(c) (c == ' ' || c == '\t')

static char __parse_hostname(const char **str, ssize_t len, char **out)
{
	char retval = 0;

	/* TODO we usually take the host from iri->host. Check that IRI already encodes spaces. */
	if (sscanf(*str, "%ms", out) != 1)
		goto end;

	(*str) += strlen(*out);
	if (isspace(**str) || **str == '\0')
		retval = 1;

end:
	return retval;
}

static char __next_token(const char **str)
{
	char retval = 0;

	while (**str) {
		if (!isspace(**str))
			break;
		(*str)++;
	}

	if (**str)
		retval = 1;

	return retval;
}

static char __parse_number_unsigned(const char **str, ssize_t len, unsigned long int *out)
{
	char retval = 0;
	unsigned int i;
	char dst[len + 1];

	for (i = 0; i < len && **str; i++) {
		if (isdigit(**str))
			dst[i] = *((*str)++);
		else if (isspace(**str))
			break;
		else
			goto end;
	}

	if (i > 0) {
		/*
		 * Perform some sanity checks. We don't allow octal numbers.
		 * We also don't allow other weird tricks such as prepending +/-
		 * or "0x", but these must have been detected by the for loop above.
		 */
		if (dst[0] == '0' && i > 1)
			goto end;

		dst[i] = '\0';
		*out = strtoul(dst, NULL, 10);
		retval = 1;
	}

end:
	return retval;
}

static char __parse_digit(const char **str, unsigned char *out)
{
	char retval = 0;

	if (isdigit(**str)) {
		/* 48 is the ASCII value for '0' */
		*out = *((*str)++) - 48;
		retval = 1;
	}

	return retval;
}

static int __wget_hpkp_parse_host_line(const char *line, ssize_t len,
		char **host_out,
		time_t *created, time_t *max_age, unsigned char *include_subdomains,
		unsigned int *num_pins)
{
	wget_iri_t *iri = NULL;
	int retval = -1;

	if (!__parse_hostname(&line, len, host_out))
		goto end;
	/* We try to parse the host here to verify if it's valid */
	/* TODO should we store the encoding in the database file as well? */
	/* TODO maybe we should add a new field 'encoding' to wget_iri_t */
	iri = wget_iri_parse(*host_out, "utf-8");
	if (!iri)
		goto end;
	if (iri->is_ip_address) {
		wget_error_printf("Host '%s' is a literal IP address. Skipping.\n", iri->host);
		goto end;
	}

	/* Parse created */
	if (!(__next_token(&line) && __parse_number_unsigned(&line, len, (unsigned long int *) created)))
		goto end;

	/* Parse max-age */
	if (!(__next_token(&line) && __parse_number_unsigned(&line, len, (unsigned long int *) max_age)))
		goto end;

	/* Parse include subdomains */
	if (!(__next_token(&line) && __parse_digit(&line, include_subdomains)) ||
			(*include_subdomains > 1))
		goto end;

	/* Parse number of pins */
	if (!(__next_token(&line) && __parse_number_unsigned(&line, len, (unsigned long int *) num_pins)))
		goto end;

	if (*num_pins > 0) {
		retval = 0;
		wget_info_printf("Processing %u public key pins for host '%s'\n", *num_pins, *host_out);
	} else {
		wget_error_printf("No pins found\n");
	}

end:
	if (iri)
		wget_iri_free(&iri);
	return retval;
}

static int __wget_hpkp_parse_pin_line(const char *line, ssize_t len, char **b64_pin)
{
	int retval = -1;
	char sha256_magic[len + 1];

	if (sscanf(line, "%s\t%ms", sha256_magic, b64_pin) != 2)
		goto end;
	/* Same as before. Only SHA-256 is supported for now. */
	if (wget_strcmp(sha256_magic, "sha-256")) {
		wget_error_printf("Only 'sha-256' hashes are supported.\n");
		goto end;
	}

	/* Everything OK */
	retval = 0;

end:
	return retval;
}

int wget_hpkp_db_load(const char *filename, wget_hpkp_db_t *hpkp_db)
{
	int retval = 0;
	FILE *fp;
	char *buf, should_continue = 1;
	size_t bufsize = 0;
	ssize_t buflen;
	char *host = NULL;
	time_t created, max_age;
	unsigned char include_subdomains;
	unsigned int num_pins = 0;
	char *b64_pin = NULL;
	wget_hpkp_t *hpkp = NULL;

	if (!filename || !*filename || !hpkp_db)
		return WGET_HPKP_ERROR;

	fp = fopen(filename, "r");
	if (!fp)
		return WGET_HPKP_ERROR_FILE_OPEN;

	do {
		buflen = wget_getline(&buf, &bufsize, fp);
		if (buflen >= 0 && buf[0] != '#') {
			retval = __wget_hpkp_parse_host_line(buf, buflen,
					&host,
					&created, &max_age, &include_subdomains,
					&num_pins);
			if (retval == -1) {
				wget_error_printf("HPKP: could not parse host line '%s'\n", buf);
				retval = WGET_HPKP_ERROR;
				should_continue = 0;
				goto end;
			}

			hpkp = wget_hpkp_new(host, created, max_age, include_subdomains);
			for (int pin = 0; pin < num_pins; pin++) {
				/* Read next line */
				buflen = wget_getline(&buf, &bufsize, fp);
				if (buflen < 0) {
					wget_error_printf("HPKP: %d SPKIs were specified but only %d were found\n", num_pins, pin + 1);
					retval = WGET_HPKP_ERROR;
					should_continue = 0;
					goto end;
				}

				/* Try to parse it as a SPKI line */
				retval = __wget_hpkp_parse_pin_line(buf, buflen, &b64_pin);
				if (retval == -1) {
					wget_error_printf("HPKP: could not parse pin line '%s'\n", buf);
					retval = WGET_HPKP_ERROR;
					should_continue = 0;
					goto end;
				}
				__wget_hpkp_db_put_base64_spki(hpkp, b64_pin);
			}

			switch (__wget_hpkp_db_add(hpkp_db, hpkp, 1)) {
			case WGET_HPKP_OK:
				wget_info_printf("HPKP: Added pinned SPKIs for host '%s'.\n", host);
				break;
			case WGET_HPKP_ENTRY_EXPIRED:
				wget_info_printf("HPKP: Pinned SPKIs for host '%s' have expired. Ignored.\n", host);
				__wget_hpkp_free(hpkp, 1);
				break;
			case WGET_HPKP_NOT_ENOUGH_PINS:
				wget_error_printf("HPKP: Host '%s' must have at least 2 pinned SPKIs. Ignored.\n", host);
				__wget_hpkp_free(hpkp, 1);
				break;
			case WGET_HPKP_ENTRY_EXISTS:
				wget_error_printf("HPKP: Host '%s' is repeated. Ignored.\n", host);
				__wget_hpkp_free(hpkp, 1);
				break;
			default:
				__wget_hpkp_free(hpkp, 1);
				break;
			}

end:
			xfree(b64_pin);
			xfree(host);
		} else if (buflen < 0) {
			should_continue = 0;
		}
	} while (should_continue);

	xfree(buf);

	fclose(fp);
	return retval;
}
