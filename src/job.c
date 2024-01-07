/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Job routines
 *
 * Changelog
 * 04.06.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <wget.h>

#include "wget_main.h"
//#include "wget_log.h"
#include "wget_job.h"

void job_free(JOB *job)
{
	if (job->challenges_alloc)
		wget_http_free_challenges(&job->challenges);
	wget_http_free_challenges(&job->proxy_challenges);
	wget_metalink_free(&job->metalink);
	wget_vector_free(&job->parts);
	wget_list_free(&job->remaining_sig_ext);
	xfree(job->sig_req);
	xfree(job->sig_filename);
}

void job_create_parts(JOB *job)
{
	PART part;
	wget_metalink *metalink;
	ssize_t fsize;

	if (!(metalink = job->metalink))
		return;

	memset(&part, 0, sizeof(PART));

	// create space to hold enough parts
	if (!job->parts)
		job->parts = wget_vector_create(wget_vector_size(metalink->pieces), NULL);
	else
		wget_vector_clear(job->parts);

	fsize = metalink->size;

	for (int it = 0; it < wget_vector_size(metalink->pieces); it++) {
		wget_metalink_piece *piece = wget_vector_get(metalink->pieces, it);

		if (fsize >= piece->length) {
			part.length = piece->length;
		} else {
			part.length = fsize;
		}

		part.id = it + 1;

		wget_vector_add_memdup(job->parts, &part, sizeof(PART));

		part.position += part.length;
		fsize -= piece->length;
	}
}

// check hash for part of a file
// -1: error
//  0: not ok
//  1: ok

static int check_piece_hash(wget_metalink_hash *hash, int fd, off_t offset, size_t length)
{
	char sum[128 + 1]; // large enough for sha-512 hex

	if (wget_hash_file_fd(hash->type, fd, sum, sizeof(sum), offset, length) != -1) {
		return !wget_strcasecmp_ascii(sum, hash->hash_hex);
	}

	return -1;
}

/*
// check hash for complete file
//  0: not ok
//  1: ok

static int check_file_hash(HASH *hash, const char *fname)
{
	char sum[128 + 1]; // large enough for sha-512 hex

	if (hash_file(hash->type, fname, sum, sizeof(sum)) != -1) {
		return !wget_strcasecmp_ascii(sum, hash->hash_hex);
	}
	return -1;
}
*/

static int check_file_fd(wget_metalink_hash *hash, int fd)
{
	char sum[128 + 1]; // large enough for sha-512 hex

	if (wget_hash_file_fd(hash->type, fd, sum, sizeof(sum), 0, 0) != -1) {
		return !wget_strcasecmp_ascii(sum, hash->hash_hex);
	}

	return -1;
}

int job_validate_file(JOB *job)
{
	PART part;
	wget_metalink *metalink;
	off_t fsize, real_fsize = 0;
	int fd;
	struct stat st;

	if (!(metalink = job->metalink))
		return 0;

	memset(&part, 0, sizeof(PART));

	// Metalink may be used without pieces...
	if (!metalink->pieces) {
		wget_metalink_piece piece;
		wget_metalink_hash *hash = wget_vector_get(metalink->hashes, 0);

		if (!hash)
			return 1;

		piece.length = metalink->size;
		piece.position = 0;
		wget_strscpy(piece.hash.type, hash->type, sizeof(piece.hash.type));
		wget_strscpy(piece.hash.hash_hex, hash->hash_hex, sizeof(piece.hash.hash_hex));

		metalink->pieces = wget_vector_create(1, NULL);
		wget_vector_add_memdup(metalink->pieces, &piece, sizeof(wget_metalink_piece));
	}

	// create space to hold enough parts
	if (!job->parts)
		job->parts = wget_vector_create(wget_vector_size(metalink->pieces), NULL);
	else
		wget_vector_clear(job->parts);

	fsize = metalink->size;
//	info_printf("metalink->name = %s\n", metalink->name);
//	info_printf("metalink->size = %zu\n", metalink->size);
//	info_printf("metalink->hashes = %d\n", wget_vector_size(metalink->hashes));

	if (wget_vector_size(metalink->hashes) == 0) {
		// multipart non-metalink download: do not clobber if file has expected size
		if (stat(metalink->name, &st) == 0 && st.st_size == fsize) {
			return 1; // we are done
		}
	}

	// truncate file if needed
	if (stat(metalink->name, &st) == 0 && (real_fsize = st.st_size) > fsize) {
		if (wget_truncate(metalink->name, fsize) != WGET_E_SUCCESS)
			error_printf(_("Failed to truncate %s\n from %llu to %llu bytes\n"),
				metalink->name, (unsigned long long)st.st_size, (unsigned long long)fsize);
		else
			real_fsize = fsize;
	}

	if (wget_vector_size(metalink->hashes) > 0 && (fd = open(metalink->name, O_RDONLY|O_BINARY)) != -1) {
		// file exists, check which piece is invalid and re-queue it
		int rc = -1;
		for (int it = 0; errno != EINTR && it < wget_vector_size(metalink->hashes); it++) {
			wget_metalink_hash *hash = wget_vector_get(metalink->hashes, it);

			if ((rc = check_file_fd(hash, fd)) == -1)
				continue; // hash type not available, try next

			break;
		}

		if (rc == 1) {
			info_printf(_("Checksum OK for '%s'\n"), metalink->name);
			close(fd);
			return 1; // we are done
		}

		if (rc == -1) {
			// failed to check file, continue as if file is ok
			info_printf(_("Failed to build checksum, assuming file to be OK\n"));
			close(fd);
			return 1; // we are done
		}

		info_printf(_("Bad checksum for '%s'\n"), metalink->name);

//		if (vec_size(metalink->pieces) < 1)
//			return;

		for (int it = 0; errno != EINTR && it < wget_vector_size(metalink->pieces); it++) {
			wget_metalink_piece *piece = wget_vector_get(metalink->pieces, it);
			wget_metalink_hash *hash = &piece->hash;

			if (fsize >= piece->length) {
				part.length = piece->length;
			} else {
				part.length = (size_t)fsize;
			}

			part.id = it + 1;

			if (check_piece_hash(hash, fd, part.position, part.length) != 1) {
				info_printf(_("Piece %d/%d not OK - requeuing\n"), it + 1, wget_vector_size(metalink->pieces));
				wget_vector_add_memdup(job->parts, &part, sizeof(PART));
				debug_printf("  need to download %llu bytes from pos=%llu\n",
					(unsigned long long)part.length, (unsigned long long)part.position);
			}

			part.position += part.length;
			fsize -= piece->length;
		}
		close(fd);
	} else {
//		info_printf("real_fsize = %lld\n", (long long) real_fsize);

		for (int it = 0; it < wget_vector_size(metalink->pieces); it++) {
			wget_metalink_piece *piece = wget_vector_get(metalink->pieces, it);

			if (fsize >= piece->length) {
				part.length = piece->length;
			} else {
				part.length = fsize;
			}

			part.id = it + 1;

//			info_printf("real_fsize = %lld %lld\n", (long long) real_fsize, part.position + part.length);

			if (real_fsize < part.position + part.length) {
				int idx = wget_vector_add_memdup(job->parts, &part, sizeof(PART));

				if (real_fsize > part.position) {
					PART *p = wget_vector_get(job->parts, idx);
					p->position = real_fsize;
					p->length = (part.position + part.length) - real_fsize;
				}
			}

			part.position += part.length;
			fsize -= piece->length;
		}
	}

	return 0;
}

JOB *job_init(JOB *job, blacklist_entry *blacklistp, bool http_fallback)
{
	static unsigned long long jobid;

	if (!job)
		job = wget_calloc(1, sizeof(JOB));
	else
		memset(job, 0, sizeof(JOB));

	job->blacklist_entry = blacklistp;
	job->iri = blacklistp->iri; // convenience assignment
	job->http_fallback = http_fallback;
	job->id = ++jobid;

	return job;
}
