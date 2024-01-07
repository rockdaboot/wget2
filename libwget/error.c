/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Error functions
 * \defgroup libwget-error Error functions
 * @{
 *
 * Here are th implementations of libwget error functions.
 */

/**
 * \param[in] rc Error code from another libwget function
 * \return A humanly readable string describing error
 *
 * Convert an internal libwget error code to a humanly readable string.
 * The returned pointer must not be de-allocated by the caller.
 */
const char *wget_strerror(wget_error err)
{
	switch (err) {
	case WGET_E_SUCCESS: return _("Success");
	case WGET_E_UNKNOWN: return _("General error");
	case WGET_E_MEMORY: return _("No memory");
	case WGET_E_INVALID: return _("Invalid value");
	case WGET_E_TIMEOUT: return _("Timeout");
	case WGET_E_CONNECT: return _("Connect error");
	case WGET_E_HANDSHAKE: return _("Handshake error");
	case WGET_E_CERTIFICATE: return _("Certificate error");
	case WGET_E_TLS_DISABLED: return _("libwget has been built without TLS support");
	case WGET_E_XML_PARSE_ERR: return _("Failed to parse XML");
	case WGET_E_OPEN: return _("Failed to open file");
	case WGET_E_IO: return _("I/O error");
	case WGET_E_UNSUPPORTED: return _("Unsupported function");
	default: return _("Unknown error");
	}
}

/**@}*/
