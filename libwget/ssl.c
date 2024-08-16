/*
 * Copyright (c) 2023-2024 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Shared code for the TLS/SSL implementations.
 */

#include <config.h>

#include <wget.h>

#ifndef _WIN32

const char *wget_ssl_default_cert_dir(void)
{
	return "/etc/ssl/certs";
}

const char *wget_ssl_default_ca_bundle_path(void)
{
	return NULL;
}

#else // _WIN32

#include <stdlib.h> // getenv
#include "filename.h" // ISSLASH

#include "private.h"

static const char *ssl_default_certdir_path;
static const char *ssl_default_certbundle_path;

// ssl_default_path() is only called once in tls_init().
static const char *ssl_default_path(const char *base)
{
	if (access("/etc/ssl/certs", F_OK) == 0) {
		return wget_strdup("/etc/ssl/certs");
	}

	const char *progData = getenv("ProgramData");

	return wget_aprintf("%s%s%s%s",
		progData ? progData : "/ProgramData",
		ISSLASH(progData[strlen(progData - 1)]) ? "" : "/",
		"ssl/",
		base);
}

const char *wget_ssl_default_cert_dir(void)
{
	if (!ssl_default_certdir_path)
		ssl_default_certdir_path = ssl_default_path("certs/");
	return ssl_default_certdir_path;
}

const char *wget_ssl_default_ca_bundle_path(void)
{
	if (!ssl_default_certbundle_path)
		ssl_default_certbundle_path = ssl_default_path("ca-bundle.pem");
	return access(ssl_default_certbundle_path, F_OK) == 0 ? ssl_default_certbundle_path: NULL;
}
#endif
