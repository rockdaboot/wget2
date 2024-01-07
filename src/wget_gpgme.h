/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * GPGME Helper Routines, Header File
 *
 * Changelog
 * 04.09.2017  Darshit Shah created
 *
 */

#ifndef SRC_WGET_GPGME_H
#define SRC_WGET_GPGME_H

#include <config.h>

#include <wget.h>
#include <wget_job.h>

//definition of gpg error conditions
typedef enum {
	WGET_E_GPG_DISABLED = -9, /* GPGME was not enabled at compile time */
	WGET_E_GPG_VER_FAIL = -10, /* 1 or more non-valid signatures */
	WGET_E_GPG_VER_ERR = -11, /* Verification failed, GPGME error */
} wget_gpg_error;

/**
 * Statistics about a certain verification.
 */
typedef struct {
	int bad_sigs; //!< Total number of bad signatures
	int missing_sigs; //!< Total number of missing public keys
	int invalid_sigs; //!< Total number of valid signatures
	int valid_sigs; //!< Total number of invalid signatures
} wget_gpg_info_t;

/**
 * Initialize gpgme (and the wget gpgme code).
 */
void init_gpgme(void);

/**
 * Verify signature file from job and http response.
 *
 * \param job The JOB that needs to be verified.
 * \param resp The response for the request for the signature.
 * \param info The struct that will be populated with
 *             information about the verification. Pass in NULL if you don't care.
 * \return A wget error code. See wget_verify_pgp_sig_str return value for more info.
 */
int wget_verify_job(JOB *job, wget_http_response *resp, wget_gpg_info_t *info);

/**
 * Verify signature data contained in buffers
 *
 * \param sig The buffer containing the signature data.
 * \param data The buffer containing the signed data.
 * \param info The struct that will be populated with
 *             information about the verification. Pass in NULL if you don't care.
 * \return A wget error code. See wget_verify_pgp_sig_str return value for more info.
 */
int wget_verify_pgp_sig_buff(wget_buffer *sig, wget_buffer *data, wget_gpg_info_t *info);

/**
 * Verify signature contained in char arrays.
 *
 * \param sig The bytes containing the signature.
 * \param sig_len The number of bytes in sig.
 * \param data The bytes for the signed data.
 * \param data_len The number of bytes in data.
 * \param info The struct that will be populated with
 *        information about the verification. Pass in NULL if you don't care.
 * \return A wget error code.
 *         Return Codes:
 *             - WGET_E_SUCCESS: Verification was successful.
 *             - WGET_E_INVALID: Invalid input.
 *             - WGET_E_GPG_DISABLED: Wasn't compiled with GPGME support.
 *             - WGET_E_GPG_VER_FAIL: Verification failed.
 *             - WGET_E_GPG_VER_ERR: GPGME error, verification failed.
 */
int wget_verify_pgp_sig_str(const char *sig,
			    const size_t sig_len,
			    const char *data,
			    const size_t data_len,
			    wget_gpg_info_t *info);

/**
 * Computes the base file for the JOB (the JOB must be a signature file).
 *
 * \param job The job to get the corresponding base file for
 * \return A newly allocated string with the path to the base file that was signed,
 *         or NULL if the JOB wasn't a signature file, or it couldn't be computed.
 *
 */
char *wget_verify_get_base_file(JOB *job);

#endif /* SRC_WGET_GPGME_H */
