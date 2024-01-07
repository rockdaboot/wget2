/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * Stub functions for building without SSL/TLS
 *
 */

#include <config.h>

#include <stddef.h>

#include <wget.h>
#include "private.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"
void wget_ssl_set_config_string(int key, const char *value) { }
void wget_ssl_set_config_object(int key, void *value) { }
void wget_ssl_set_config_int(int key, int value) { }
void wget_ssl_init(void) { }
void wget_ssl_deinit(void) { }
int wget_ssl_open(wget_tcp *tcp) { return WGET_E_TLS_DISABLED; }
void wget_ssl_close(void **session) { }
ssize_t wget_ssl_read_timeout(void *session, char *buf, size_t count, int timeout) { return 0; }
ssize_t wget_ssl_write_timeout(void *session, const char *buf, size_t count, int timeout) { return 0; }
void wget_ssl_set_stats_callback_tls(wget_tls_stats_callback fn, void *ctx) { }
void wget_ssl_set_stats_callback_ocsp(wget_ocsp_stats_callback fn, void *ctx) { }

/** @} */
