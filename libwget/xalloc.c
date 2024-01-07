/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Memory allocation routines
 *
 * Changelog
 * 25.06.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Memory allocation functions
 * \defgroup libwget-xalloc Memory allocation functions
 * @{
 *
 * Global function pointers to memory allocation functions and to free().
 *
 * These pointers can be set to custom functions.
 */

wget_malloc_function *wget_malloc_fn = malloc;
wget_calloc_function *wget_calloc_fn = calloc;
wget_realloc_function *wget_realloc_fn = realloc;
wget_free_function *wget_free = free;

/**@}*/
