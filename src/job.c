/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Job routines
 *
 * Changelog
 * 04.06.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <libmget.h>

#include "mget.h"
#include "log.h"
#include "job.h"

static mget_list_t
	*queue;

void job_free(JOB *job)
{
	if (job) {
		mget_metalink_free(&job->metalink);
		mget_vector_free(&job->parts);
		mget_vector_clear_nofree(job->deferred);
		mget_vector_free(&job->deferred);
		xfree(job->local_filename);
	}
}

void job_create_parts(JOB *job)
{
	PART part;
	mget_metalink_t *metalink;
	ssize_t fsize;
	int it;

	if (!job || !(metalink = job->metalink))
		return;

	memset(&part, 0, sizeof(PART));

	// create space to hold enough parts
	if (!job->parts)
		job->parts = mget_vector_create(mget_vector_size(metalink->pieces), 4, NULL);
	else
		mget_vector_clear(job->parts);

	fsize = metalink->size;

	for (it = 0; it < mget_vector_size(metalink->pieces); it++) {
		mget_metalink_piece_t *piece = mget_vector_get(metalink->pieces, it);

		if (fsize >= piece->length) {
			part.length = piece->length;
		} else {
			part.length = fsize;
		}

		part.id = it + 1;

		mget_vector_add(job->parts, &part, sizeof(PART));

		part.position += part.length;
		fsize -= piece->length;
	}
}

/*
void job_create_parts(JOB *job)
{
	PART part;
	size_t partsize;
	ssize_t fsize = job->size;

	// calculate size of parts to be downloaded
#define MAX_PARTSIZE 5*1024*1024
	PIECE *piece = vec_get(job->pieces, 0);
	if (piece) {
		if (piece->length < MAX_PARTSIZE) {
			partsize = (MAX_PARTSIZE / piece->length) * piece->length;
		} else {
			partsize = piece->length;
		}
	} else {
		partsize = MAX_PARTSIZE;
	}
#undef MAX_PARTSIZE

	// create space to hold enough parts
	if (!job->parts)
		job->parts = vec_create((fsize + partsize - 1) / partsize, 4, NULL);

	memset(&part, 0, sizeof(PART));
	do {
		if (fsize >= partsize) {
			part.length = partsize;
		} else {
			part.length = fsize;
		}
		vec_add(job->parts, &part, sizeof(PART));
		part.position += part.length;
		fsize -= partsize;
	} while (fsize > 0);
}
*/

/*
PART *job_add_part(JOB *job, PART *part)
{
	if (!job->parts)
		job_create_parts(job);

	return mget_vector_get(job->parts, mget_vector_add(job->parts, part, sizeof(PART)));
}
*/

// check hash for part of a file
// -1: error
//  0: not ok
//  1: ok

static int check_piece_hash(mget_metalink_hash_t *hash, int fd, off_t offset, size_t length)
{
	char sum[128 + 1]; // large enough for sha-512 hex

	if (mget_hash_file_fd(hash->type, fd, sum, sizeof(sum), offset, length) != -1) {
		return !strcasecmp(sum, hash->hash_hex);
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
		return !strcasecmp(sum, hash->hash_hex);
	}
 	return -1;
}
*/

static int check_file_fd(mget_metalink_hash_t *hash, int fd)
{
	char sum[128 + 1]; // large enough for sha-512 hex

	if (mget_hash_file_fd(hash->type, fd, sum, sizeof(sum), 0, 0) != -1) {
		return !strcasecmp(sum, hash->hash_hex);
	}

	return -1;
}

int job_validate_file(JOB *job)
{
	PART part;
	mget_metalink_t *metalink;
	off_t fsize;
	int fd, rc = -1, it;
	struct stat st;

	if (!job || !(metalink = job->metalink))
		return 0;

	memset(&part, 0, sizeof(PART));

	// create space to hold enough parts
	if (!job->parts)
		job->parts = mget_vector_create(mget_vector_size(metalink->pieces), 4, NULL);
	else
		mget_vector_clear(job->parts);

	fsize = metalink->size;

	if (mget_vector_size(metalink->hashes) == 0) {
		// multipart non-metalink download: do not clobber if file has expected size
		if (stat(metalink->name, &st) == 0 && st.st_size == fsize) {
			return 1; // we are done
		}
	}

	// truncate file if needed
	if (stat(metalink->name, &st) == 0 && st.st_size > fsize) {
		if (truncate(metalink->name, fsize) == -1)
			error_printf(_("Failed to truncate %s\n from %llu to %llu bytes\n"),
				metalink->name, (unsigned long long)st.st_size, (unsigned long long)fsize);
	}

	if ((fd = open(metalink->name, O_RDONLY)) != -1) {
		// file exists, check which piece is invalid and requeue it

		for (it = 0; errno != EINTR && it < mget_vector_size(metalink->hashes); it++) {
			mget_metalink_hash_t *hash = mget_vector_get(metalink->hashes, it);

			if ((rc = check_file_fd(hash, fd)) == -1)
				continue; // hash type not available, try next

			break;
		}

		if (rc == 1) {
			info_printf(_("Checksum OK for '%s'\n"), metalink->name);
			return 1; // we are done
		}
		else if (rc == -1) {
			// failed to check file, continue as if file is ok
			info_printf(_("Failed to build checksum, assuming file to be OK\n"));
			return 1; // we are done
		} else
			info_printf(_("Bad checksum for '%s'\n"), metalink->name);

//		if (vec_size(metalink->pieces) < 1)
//			return;

		for (it = 0; errno != EINTR && it < mget_vector_size(metalink->pieces); it++) {
			mget_metalink_piece_t *piece = mget_vector_get(metalink->pieces, it);
			mget_metalink_hash_t *hash = &piece->hash;

			if (fsize >= piece->length) {
				part.length = piece->length;
			} else {
				part.length = (size_t)fsize;
			}

			part.id = it + 1;

			if ((rc = check_piece_hash(hash, fd, part.position, part.length)) != 1) {
				info_printf(_("Piece %d/%d not OK - requeuing\n"), it + 1, mget_vector_size(metalink->pieces));
				mget_vector_add(job->parts, &part, sizeof(PART));
				debug_printf("  need to download %llu bytes from pos=%llu\n",
					(unsigned long long)part.length, (unsigned long long)part.position);
			}

			part.position += part.length;
			fsize -= piece->length;
		}
		close(fd);
	} else {
		for (it = 0; it < mget_vector_size(metalink->pieces); it++) {
			mget_metalink_piece_t *piece = mget_vector_get(metalink->pieces, it);

			if (fsize >= piece->length) {
				part.length = piece->length;
			} else {
				part.length = fsize;
			}

			part.id = it + 1;

			mget_vector_add(job->parts, &part, sizeof(PART));

			part.position += part.length;
			fsize -= piece->length;
		}
	}

	return 0;
}

static mget_thread_mutex_t
	mutex = MGET_THREAD_MUTEX_INITIALIZER;

JOB *queue_add(mget_iri_t *iri)
{
	if (iri) {
		JOB job = { .iri = iri }, *jobp;

		mget_thread_mutex_lock(&mutex);
		jobp = mget_list_append(&queue, &job, sizeof(JOB));
		mget_thread_mutex_unlock(&mutex);

		debug_printf("queue_add %p %s\n", (void *)jobp, iri->uri);
		return jobp;
	}

	return NULL;
}

void queue_del(JOB *job)
{
	if (job) {
		debug_printf("queue_del %p\n", (void *)job);

		// special handling for automatic robots.txt jobs
		if (job->deferred) {
			if (job->host)
				job->host->robot_job = NULL;
			mget_iri_free(&job->iri);
			for (int it = 0; it < mget_vector_size(job->deferred); it++) {
				JOB *new_job = queue_add(mget_vector_get(job->deferred, it));
				new_job->local_filename = get_local_filename(new_job->iri);
			}
		}

		job_free(job);

		mget_thread_mutex_lock(&mutex);
		mget_list_remove(&queue, job);
		mget_thread_mutex_unlock(&mutex);
	}
}

struct find_free_job_context {
	JOB **job;
	PART **part;
};

// did I say, that I like nested function instead using contexts !?
// gcc, IBM and Intel support nested functions, just clang refuses it

static int find_free_job(struct find_free_job_context *context, JOB *job)
{
	// debug_printf("%p %p %p %d\n",part_out,job,job->parts,job->inuse);
	if (context->part && job->parts) {
		int it;
		// debug_printf("nparts %d\n",vec_size(job->parts));

		for (it = 0; it < mget_vector_size(job->parts); it++) {
			PART *part = mget_vector_get(job->parts, it);
			if (!part->inuse) {
				part->inuse = 1;
				*context->part = part;
				*context->job = job;
				debug_printf("queue_get part %d/%d %s\n", it + 1, mget_vector_size(job->parts), job->local_filename);
				return 1;
			}
		}
	} else if (!job->inuse) {
		job->inuse = 1;
		*context->job = job;
		debug_printf("queue_get job %s\n", job->iri->uri);
		return 1;
	}
	return 0;
}

int queue_get(JOB **job, PART **part)
{
	struct find_free_job_context
		context = { .job = job, .part = part };

	*job = NULL;
	if (part)
		*part = NULL;

	mget_thread_mutex_lock(&mutex);
	int ret = mget_list_browse(queue, (int(*)(void *, void *))find_free_job, &context);
	mget_thread_mutex_unlock(&mutex);

	return ret;
}

int queue_empty(void)
{
	return !queue;
}

// did I say, that I like nested function instead using contexts !?
// gcc, IBM and Intel support nested functions, just clang refuses it

static int queue_free_func(void *context G_GNUC_MGET_UNUSED, JOB *job)
{
	job_free(job);
	return 0;
}

void queue_free(void)
{
	mget_thread_mutex_lock(&mutex);
	mget_list_browse(queue, (int(*)(void *, void *))queue_free_func, NULL);
	mget_list_free(&queue);
	mget_thread_mutex_unlock(&mutex);
}

static int queue_print_func(void *context G_GNUC_MGET_UNUSED, JOB *job)
{
	info_printf("%s %d\n", job->local_filename, job->inuse);
	return 0;
}

void queue_print(void)
{
	mget_thread_mutex_lock(&mutex);
	mget_list_browse(queue, (int(*)(void *, void *))queue_print_func, NULL);
	mget_thread_mutex_unlock(&mutex);
}
