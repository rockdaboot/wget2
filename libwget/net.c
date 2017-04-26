/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * network routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 16.11.2012               new functions tcp_set_family() and tcp_set_preferred_family()
 *
 * RFC 7413: TCP Fast Open
 */

#if HAVE_CONFIG_H
#	include <config.h>
#endif

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <c-ctype.h>
#include <time.h>
#include <errno.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#elif defined HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
#endif
#include <netdb.h>
#include <netinet/in.h>

#ifdef HAVE_NETINET_TCP_H
#	include <netinet/tcp.h>
#endif

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#if defined __APPLE__ && defined __MACH__ && defined CONNECT_DATA_IDEMPOTENT && defined CONNECT_RESUME_ON_READ_WRITE
# define TCP_FASTOPEN_OSX
#elif defined TCP_FASTOPEN && defined MSG_FASTOPEN
# define TCP_FASTOPEN_LINUX
#endif

#include <wget.h>
#include "private.h"
#include "net.h"

// resolver / DNS cache entry
struct ADDR_ENTRY {
	const char *
		host;
	const char *
		port;
	struct addrinfo *
		addrinfo;
};

static struct wget_tcp_st _global_tcp = {
	.sockfd = -1,
	.dns_timeout = -1,
	.connect_timeout = -1,
	.timeout = -1,
	.family = AF_UNSPEC,
	.caching = 1,
#if defined TCP_FASTOPEN_OSX
	.tcp_fastopen = 1,
#elif defined TCP_FASTOPEN_LINUX
	.tcp_fastopen = 1,
	.first_send = 1
#endif
};

// resolver / DNS cache container
static wget_vector_t
	*dns_cache;
static wget_thread_mutex_t
	dns_mutex = WGET_THREAD_MUTEX_INITIALIZER;

static struct addrinfo *_wget_dns_cache_get(const char *host, const char *port)
{
	if (dns_cache) {
		struct ADDR_ENTRY *entryp, entry = { .host = host, .port = port };
		int index;

		wget_thread_mutex_lock(&dns_mutex);
		entryp = wget_vector_get(dns_cache, (index = wget_vector_find(dns_cache, &entry)));
		wget_thread_mutex_unlock(&dns_mutex);

		if (entryp) {
			// DNS cache entry found
			debug_printf("Found dns cache entry #%d\n", index);
			return entryp->addrinfo;
		}
	}

	return NULL;
}

static int G_GNUC_WGET_PURE _compare_addr(struct ADDR_ENTRY *a1, struct ADDR_ENTRY *a2)
{
	int n;

	if ((n = wget_strcasecmp(a1->host, a2->host)) == 0)
		return wget_strcasecmp_ascii(a1->port, a2->port);

	return n;
}

static void _free_dns(struct ADDR_ENTRY *entry)
{
	freeaddrinfo(entry->addrinfo);
}

static struct addrinfo * _wget_dns_cache_add(const char *host, const char *port, struct addrinfo *addrinfo)
{
	// insert addrinfo into dns cache
	size_t hostlen = host ? strlen(host) + 1 : 0;
	size_t portlen = port ? strlen(port) + 1 : 0;
	struct ADDR_ENTRY *entryp = xmalloc(sizeof(struct ADDR_ENTRY) + hostlen + portlen);
	int index;

	if (host) {
		entryp->host = ((char *)entryp) + sizeof(struct ADDR_ENTRY);
		memcpy((char *)entryp->host, host, hostlen); // ugly cast, but semantically ok
	} else
		entryp->host = NULL;

	if (port) {
		entryp->port = ((char *)entryp) + sizeof(struct ADDR_ENTRY) + hostlen;
		memcpy((char *)entryp->port, port, portlen); // ugly cast, but semantically ok
	} else
		entryp->port = NULL;

	entryp->addrinfo = addrinfo;

	wget_thread_mutex_lock(&dns_mutex);
	if (!dns_cache) {
		dns_cache = wget_vector_create(4, -2, (wget_vector_compare_t)_compare_addr);
		wget_vector_set_destructor(dns_cache, (wget_vector_destructor_t)_free_dns);
	}

	if ((index = wget_vector_find(dns_cache, entryp)) == -1) {
		debug_printf("Add dns cache entry %s:%s\n", host, port);
		wget_vector_insert_sorted_noalloc(dns_cache, entryp);
	} else {
		// race condition:
		xfree(entryp);
		freeaddrinfo(addrinfo);
		addrinfo = wget_vector_get(dns_cache, index);
	}
	wget_thread_mutex_unlock(&dns_mutex);

	return addrinfo;
}

void wget_dns_cache_free(void)
{
	wget_thread_mutex_lock(&dns_mutex);
	wget_vector_free(&dns_cache);
	wget_thread_mutex_unlock(&dns_mutex);
}

struct addrinfo *wget_tcp_resolve(wget_tcp_t *tcp, const char *host, const char *port)
{
	static wget_thread_mutex_t
		mutex = WGET_THREAD_MUTEX_INITIALIZER;
	struct addrinfo *addrinfo = NULL, hints;
	int rc = 0, ai_flags = 0;

	if (!tcp)
		tcp = &_global_tcp;

//	if (!port)
//		port = "0";

	// get the IP address for the server
	for (int tries = 0, max = 3; tries < max; tries++) {
		// if port is NULL,
		if (tcp->caching) {
			if ((addrinfo = _wget_dns_cache_get(host, port)))
				return addrinfo;

			// prevent multiple address resolutions of the same host/port
			wget_thread_mutex_lock(&mutex);
			// now try again
			if ((addrinfo = _wget_dns_cache_get(host, port))) {
				wget_thread_mutex_unlock(&mutex);
				return addrinfo;
			}
		}
		addrinfo = NULL;

		ai_flags |= (port && c_isdigit(*port) ? AI_NUMERICSERV : 0);
		ai_flags |= AI_ADDRCONFIG;

		if (tcp->passive) {
			ai_flags |= AI_PASSIVE;
		}

		memset(&hints, 0 ,sizeof(hints));
		hints.ai_family = tcp->family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = ai_flags;

		if (port)
			debug_printf("resolving %s:%s...\n", host, port);
		else
			debug_printf("resolving %s...\n", host);

		if ((rc = getaddrinfo(host, port, &hints, &addrinfo)) == 0 || rc != EAI_AGAIN)
			break;

		if (tries < max - 1) {
			if (tcp->caching)
				wget_thread_mutex_unlock(&mutex);
			wget_millisleep(100);
		}
	}

	if (rc) {
		error_printf(_("Failed to resolve %s:%s (%s)\n"), host, port, gai_strerror(rc));

		if (tcp->caching)
			wget_thread_mutex_unlock(&mutex);

		return NULL;
	}

	if (tcp->family == AF_UNSPEC && tcp->preferred_family != AF_UNSPEC) {
		struct addrinfo *preferred = NULL, *preferred_tail = NULL;
		struct addrinfo *unpreferred = NULL, *unpreferred_tail = NULL;

		// split address list into preferred and not preferred, keeping the original order
		for (struct addrinfo *ai = addrinfo; ai;) {
			if (ai->ai_family == tcp->preferred_family) {
				if (preferred_tail)
					preferred_tail->ai_next = ai;
				else
					preferred = ai; // remember the head of the list

				preferred_tail = ai;
				ai = ai->ai_next;
				preferred_tail->ai_next = NULL;
			} else {
				if (unpreferred_tail)
					unpreferred_tail->ai_next = ai;
				else
					unpreferred = ai; // remember the head of the list

				unpreferred_tail = ai;
				ai = ai->ai_next;
				unpreferred_tail->ai_next = NULL;
			}
		}

		// merge preferred + not preferred
		if (preferred) {
			preferred_tail->ai_next = unpreferred;
			addrinfo = preferred;
		} else {
			addrinfo = unpreferred;
		}
	}

	if (wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG))) {
		for (struct addrinfo *ai = addrinfo; ai; ai = ai->ai_next) {
			char adr[NI_MAXHOST], sport[NI_MAXSERV];

			if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
				debug_printf("has %s:%s\n", adr, sport);
			else
				debug_printf("has ???:%s (%s)\n", sport, gai_strerror(rc));
		}
	}

	if (tcp->caching) {
		// In case of a race condition the already existing addrinfo is returned.
		// The addrinfo argument given to _wget_dns_cache_add() will be freed in this case.
		addrinfo = _wget_dns_cache_add(host, port, addrinfo);
		wget_thread_mutex_unlock(&mutex);
	}

	return addrinfo;
}

static int G_GNUC_WGET_CONST _value_to_family(WGET_INET_FAMILY value)
{
	switch (value) {
	case WGET_NET_FAMILY_IPV4:
		return AF_INET;
	case WGET_NET_FAMILY_IPV6:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

static WGET_INET_FAMILY G_GNUC_WGET_CONST _family_to_value(int family)
{
	switch (family) {
	case AF_INET:
		return WGET_NET_FAMILY_IPV4;
	case AF_INET6:
		return WGET_NET_FAMILY_IPV6;
	default:
		return WGET_NET_FAMILY_ANY;
	}
}

void wget_tcp_set_tcp_fastopen(wget_tcp_t *tcp, int tcp_fastopen)
{
#if defined TCP_FASTOPEN_OSX || defined TCP_FASTOPEN_LINUX
	(tcp ? tcp : &_global_tcp)->tcp_fastopen = tcp_fastopen;
#endif
}

int wget_tcp_get_tcp_fastopen(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->tcp_fastopen;
}

void wget_tcp_set_tls_false_start(wget_tcp_t *tcp, int false_start)
{
	(tcp ? tcp : &_global_tcp)->tls_false_start = false_start;
}

int wget_tcp_get_tls_false_start(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->tls_false_start;
}

void wget_tcp_set_dns_caching(wget_tcp_t *tcp, int caching)
{
	(tcp ? tcp : &_global_tcp)->caching = caching;
}

int wget_tcp_get_dns_caching(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->caching;
}

void wget_tcp_set_protocol(wget_tcp_t *tcp, int protocol)
{
	(tcp ? tcp : &_global_tcp)->protocol = protocol;
}

int wget_tcp_get_protocol(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->protocol;
}

void wget_tcp_set_preferred_family(wget_tcp_t *tcp, int family)
{
	(tcp ? tcp : &_global_tcp)->preferred_family = _value_to_family(family);
}

int wget_tcp_get_preferred_family(wget_tcp_t *tcp)
{
	return _family_to_value((tcp ? tcp : &_global_tcp)->preferred_family);
}

void wget_tcp_set_family(wget_tcp_t *tcp, int family)
{
	(tcp ? tcp : &_global_tcp)->family = _value_to_family(family);
}

int wget_tcp_get_family(wget_tcp_t *tcp)
{
	return _family_to_value((tcp ? tcp : &_global_tcp)->family);
}

int wget_tcp_get_local_port(wget_tcp_t *tcp)
{
	if (tcp) {
		struct sockaddr_storage addr_store;
		struct sockaddr *addr = (struct sockaddr *)&addr_store;
		socklen_t addr_len = sizeof(addr_store);
		char s_port[NI_MAXSERV];

		// get automatic retrieved port number
		if (getsockname(tcp->sockfd, addr, &addr_len)==0) {
			if (getnameinfo(addr, addr_len, NULL, 0, s_port, sizeof(s_port), NI_NUMERICSERV)==0)
				return atoi(s_port);
		}
	}

	return 0;
}

void wget_tcp_set_dns_timeout(wget_tcp_t *tcp, int timeout)
{
	(tcp ? tcp : &_global_tcp)->dns_timeout = timeout;
}

void wget_tcp_set_connect_timeout(wget_tcp_t *tcp, int timeout)
{
	(tcp ? tcp : &_global_tcp)->connect_timeout = timeout;
}

void wget_tcp_set_timeout(wget_tcp_t *tcp, int timeout)
{
	(tcp ? tcp : &_global_tcp)->timeout = timeout;
}

int wget_tcp_get_timeout(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->timeout;
}

void wget_tcp_set_bind_address(wget_tcp_t *tcp, const char *bind_address)
{
	if (!tcp)
		tcp = &_global_tcp;

	if (tcp->bind_addrinfo_allocated) {
		freeaddrinfo(tcp->bind_addrinfo);
		tcp->bind_addrinfo = NULL;
	}

	if (bind_address) {
		char copy[strlen(bind_address) + 1], *s = copy;
		const char *host;

		memcpy(copy, bind_address, sizeof(copy));

		if (*s == '[') {
			// IPv6 address within brackets
			char *p = strrchr(s, ']');
			if (p) {
				host = s + 1;
				s = p + 1;
			} else {
				// something is broken
				host = s + 1;
				while (*s) s++;
			}
		} else {
			host = s;
			while (*s && *s != ':')
				s++;
		}
		if (*s == ':') {
			*s = 0;
			tcp->bind_addrinfo = wget_tcp_resolve(tcp, host, s + 1); // bind to host + specified port
		} else {
			tcp->bind_addrinfo = wget_tcp_resolve(tcp, host, NULL); // bind to host on any port
		}
		tcp->bind_addrinfo_allocated = !tcp->caching;
	}
}

void wget_tcp_set_ssl(wget_tcp_t *tcp, int ssl)
{
	(tcp ? tcp : &_global_tcp)->ssl = ssl;
}

int wget_tcp_get_ssl(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->ssl;
}

void wget_tcp_set_ssl_hostname(wget_tcp_t *tcp, const char *hostname)
{
	if (!tcp)
		tcp = &_global_tcp;

	xfree(tcp->ssl_hostname);
	tcp->ssl_hostname = wget_strdup(hostname);
}

const char *wget_tcp_get_ssl_hostname(wget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->ssl_hostname;
}

wget_tcp_t *wget_tcp_init(void)
{
	wget_tcp_t *tcp = xmalloc(sizeof(wget_tcp_t));

	*tcp = _global_tcp;
	tcp->ssl_hostname = wget_strdup(_global_tcp.ssl_hostname);

	return tcp;
}

void wget_tcp_deinit(wget_tcp_t **_tcp)
{
	wget_tcp_t *tcp;

	if (!_tcp) {
		xfree(_global_tcp.ssl_hostname);
		return;
	}

	if ((tcp = *_tcp)) {
		wget_tcp_close(tcp);

		if (tcp->bind_addrinfo_allocated) {
			freeaddrinfo(tcp->bind_addrinfo);
			tcp->bind_addrinfo = NULL;
		}
		xfree(tcp->ssl_hostname);
		xfree(tcp);
		if (_tcp)
			*_tcp = NULL;
	}
}

static void _set_async(int fd)
{
#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
	unsigned long blocking = 0;

	if (ioctl(fd, FIONBIO, &blocking))
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#else
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		error_printf_exit(_("Failed to get socket flags\n"));

	if (fcntl(fd, F_SETFL, flags | O_NDELAY) < 0)
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#endif
}

int wget_tcp_ready_2_transfer(wget_tcp_t *tcp, int flags)
{
	return wget_ready_2_transfer(tcp->sockfd, tcp->timeout, flags);
}

int wget_tcp_connect(wget_tcp_t *tcp, const char *host, const char *port)
{
	struct addrinfo *ai;
	int sockfd = -1, rc, ret = WGET_E_UNKNOWN;
	char adr[NI_MAXHOST], s_port[NI_MAXSERV];
	int debug = wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG));

	if (tcp->addrinfo_allocated)
		freeaddrinfo(tcp->addrinfo);

	tcp->addrinfo = wget_tcp_resolve(tcp, host, port);
	tcp->addrinfo_allocated = !tcp->caching;

	for (ai = tcp->addrinfo; ai; ai = ai->ai_next) {
		if (debug) {
			if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), s_port, sizeof(s_port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
				debug_printf("trying %s:%s...\n", adr, s_port);
			else
				debug_printf("trying ???:%s (%s)...\n", s_port, gai_strerror(rc));
		}

		if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) != -1) {
			int on = 1;

			_set_async(sockfd);

			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
				error_printf(_("Failed to set socket option REUSEADDR\n"));

			on = 1;
			if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
				error_printf(_("Failed to set socket option NODELAY\n"));

			if (tcp->bind_addrinfo) {
				if (debug) {
					if ((rc = getnameinfo(tcp->bind_addrinfo->ai_addr, tcp->bind_addrinfo->ai_addrlen, adr, sizeof(adr), s_port, sizeof(s_port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
						debug_printf("binding to %s:%s...\n", adr, s_port);
					else
						debug_printf("binding to ???:%s (%s)...\n", s_port, gai_strerror(rc));
				}

				if (bind(sockfd, tcp->bind_addrinfo->ai_addr, tcp->bind_addrinfo->ai_addrlen) != 0) {
					error_printf(_("Failed to bind (%d)\n"), errno);
					close(sockfd);
					return -1;
				}
			}

			if (tcp->tcp_fastopen) {
#ifdef TCP_FASTOPEN_OSX
				sa_endpoints_t endpoints = { .sae_dstaddr = ai->ai_addr, .sae_dstaddrlen = ai->ai_addrlen };
				rc = connectx(sockfd, &endpoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, NULL, 0, NULL, NULL);
				tcp->first_send = 0;
#else
				rc = 0;
				errno = 0;
				tcp->connect_addrinfo = ai;
				tcp->first_send = 1;
#endif
			} else {
				rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
				tcp->first_send = 0;
			}

			if (rc < 0
				&& errno != EAGAIN
				&& errno != EINPROGRESS
			) {
				error_printf(_("Failed to connect (%d)\n"), errno);
				ret = WGET_E_CONNECT;
				close(sockfd);
			} else {
				tcp->sockfd = sockfd;
				if (tcp->ssl) {
//					tcp->ssl_session = wget_ssl_open(tcp->sockfd, tcp->ssl_hostname, tcp->connect_timeout);
//					if (!tcp->ssl_session) {
					if ((ret = wget_ssl_open(tcp))) {
						if (ret == WGET_E_CERTIFICATE) {
							wget_tcp_close(tcp);
							break; /* stop here - the server cert couldn't be validated */
						}

						// do not free tcp->addrinfo when calling wget_tcp_close()
						struct addrinfo *ai_tmp = tcp->addrinfo;
						tcp->addrinfo = NULL;
						wget_tcp_close(tcp);
						tcp->addrinfo = ai_tmp;
						continue;
					}
				}

				return WGET_E_SUCCESS;
			}
		} else
			error_printf(_("Failed to create socket (%d)\n"), errno);
	}

	return ret;
}

int wget_tcp_listen(wget_tcp_t *tcp, const char *host, const char *port, int backlog)
{
	struct addrinfo *ai;
	int sockfd = -1, rc;
	char adr[NI_MAXHOST], s_port[NI_MAXSERV];
	int debug = wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG));

	if (tcp->bind_addrinfo_allocated)
		freeaddrinfo(tcp->bind_addrinfo);

	tcp->passive = 1;
	tcp->bind_addrinfo = wget_tcp_resolve(tcp, host, port);
	tcp->bind_addrinfo_allocated = !tcp->caching;

	for (ai = tcp->bind_addrinfo; ai; ai = ai->ai_next) {
		if (debug) {
			if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), s_port, sizeof(s_port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
				debug_printf("try to listen on %s:%s...\n", adr, s_port);
			else
				debug_printf("failed to listen on %s:%s (%s)...\n", host, s_port, gai_strerror(rc));
		}

		if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) != -1) {
			int on = 1;

			_set_async(sockfd);

			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
				error_printf(_("Failed to set socket option REUSEADDR\n"));

			on = 1;
			if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
				error_printf(_("Failed to set socket option NODELAY\n"));

#ifdef TCP_FASTOPEN_LINUX
			if (tcp->tcp_fastopen)  {
				on = 1;
				if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &on, sizeof(on)) == -1)
					error_printf(_("Failed to set socket option FASTOPEN\n"));
				tcp->first_send = 0;
			}
#endif

			if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) != 0) {
				error_printf(_("Failed to bind (%d)\n"), errno);
				close(sockfd);
				return -1;
			}

			if (listen(sockfd, backlog) == 0) {
				tcp->sockfd = sockfd;

				if (debug) {
					if (!port)
						snprintf(s_port, sizeof(s_port), "%d", wget_tcp_get_local_port(tcp));

					if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), NULL, 0, NI_NUMERICHOST)) == 0)
						debug_printf("%ssecure listen on %s:%s...\n", tcp->ssl ? "" : "in", adr, port ? port : s_port);
					else
						debug_printf("%ssecure listen on %s:%s (%s)...\n", tcp->ssl ? "" : "in", host, port ? port : s_port, gai_strerror(rc));
				}

				return 0;
			} else {
				error_printf(_("Failed to listen (%d)\n"), errno);
				close(sockfd);
			}
		} else
			error_printf(_("Failed to create socket (%d)\n"), errno);
	}

	return -1;
}

wget_tcp_t *wget_tcp_accept(wget_tcp_t *parent_tcp)
{
	int sockfd;

	// 0: no timeout / immediate
	// -1: INFINITE timeout
	if (parent_tcp->timeout) {
		if (wget_ready_2_read(parent_tcp->sockfd, parent_tcp->timeout) <= 0)
			return NULL;
	}

	if ((sockfd = accept(parent_tcp->sockfd, parent_tcp->bind_addrinfo->ai_addr, &parent_tcp->bind_addrinfo->ai_addrlen)) != -1) {
		wget_tcp_t *tcp = xmalloc(sizeof(wget_tcp_t));

		*tcp = *parent_tcp;
		tcp->sockfd = sockfd;
		tcp->ssl_hostname = NULL;
		tcp->addrinfo = NULL;
		tcp->bind_addrinfo = NULL;

		if (tcp->ssl) {
			if (wget_tcp_tls_start(tcp))
				wget_tcp_deinit(&tcp);
		}

		return tcp;
	}

	error_printf(_("Failed to accept (%d)\n"), errno);

	return NULL;
}

int wget_tcp_tls_start(wget_tcp_t *tcp)
{
	if (tcp->passive)
		return wget_ssl_server_open(tcp);
	else
		return wget_ssl_open(tcp);
}

void wget_tcp_tls_stop(wget_tcp_t *tcp)
{
	if (tcp->passive)
		wget_ssl_server_close(&tcp->ssl_session);
	else
		wget_ssl_close(&tcp->ssl_session);
}

ssize_t wget_tcp_read(wget_tcp_t *tcp, char *buf, size_t count)
{
	ssize_t rc;

	if (tcp->ssl_session) {
		rc = wget_ssl_read_timeout(tcp->ssl_session, buf, count, tcp->timeout);
	} else {
		// 0: no timeout / immediate
		// -1: INFINITE timeout
		if (tcp->timeout) {
			if ((rc = wget_ready_2_read(tcp->sockfd, tcp->timeout)) <= 0)
				return rc;
		}

//		rc = read(tcp->sockfd, buf, count);
		rc = recvfrom(tcp->sockfd, buf, count, 0, NULL, NULL);
	}

	if (rc < 0)
		error_printf(_("Failed to read %zu bytes (%d)\n"), count, errno);

	return rc;
}

ssize_t wget_tcp_write(wget_tcp_t *tcp, const char *buf, size_t count)
{
	ssize_t nwritten = 0, n;
	int rc;

	if (tcp->ssl_session)
		return wget_ssl_write_timeout(tcp->ssl_session, buf, count, tcp->timeout);

	while (count) {
#ifdef TCP_FASTOPEN_LINUX
		if (tcp->tcp_fastopen && tcp->first_send) {
			n = sendto(tcp->sockfd, buf, count, MSG_FASTOPEN,
				tcp->connect_addrinfo->ai_addr, tcp->connect_addrinfo->ai_addrlen);
			tcp->first_send = 0;

			if (n < 0 && errno == EOPNOTSUPP) {
				// fallback from fastopen, e.g. when fastopen is disabled in system
				tcp->tcp_fastopen = 0;
				rc = connect(tcp->sockfd, tcp->connect_addrinfo->ai_addr, tcp->connect_addrinfo->ai_addrlen);
				if (rc < 0
					&& errno != EAGAIN
					&& errno != ENOTCONN
					&& errno != EINPROGRESS)
				{
					error_printf(_("Failed to connect (%d)\n"), errno);
					return -1;
				}
				errno = EAGAIN;
			}
		} else
#endif

		n = send(tcp->sockfd, buf, count, 0);

		if (n >= 0) {
			if ((size_t)n >= count)
				return nwritten + n;

			count -= n;
			buf += n;
			nwritten += n;
		} else {
			if (errno != EAGAIN
				&& errno != ENOTCONN
				&& errno != EINPROGRESS
			) {
				error_printf(_("Failed to write %zu bytes (%d)\n"), count, errno);
				return -1;
			}

			// 0: no timeout / immediate
			// -1: INFINITE timeout
			if (tcp->timeout) {
				if ((rc = wget_ready_2_write(tcp->sockfd, tcp->timeout)) <= 0)
					return rc;
			}
		}
	}

	return 0;
}

ssize_t wget_tcp_vprintf(wget_tcp_t *tcp, const char *fmt, va_list args)
{
	char sbuf[4096];
	wget_buffer_t buf;
	ssize_t len2;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf(&buf, fmt, args);

	len2 = wget_tcp_write(tcp, buf.data, buf.length);

	wget_buffer_deinit(&buf);

	if (len2 > 0)
		debug_write(buf.data, len2);

	if (len2 > 0 && (ssize_t) buf.length != len2)
		error_printf("tcp_send: internal error: length mismatch %zu != %zd\n", buf.length, len2);

	return len2;
}

ssize_t wget_tcp_printf(wget_tcp_t *tcp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ssize_t len = wget_tcp_vprintf(tcp, fmt, args);
	va_end(args);

	return len;
}

void wget_tcp_close(wget_tcp_t *tcp)
{
	if (tcp) {
		wget_tcp_tls_stop(tcp);
		if (tcp->sockfd != -1) {
			close(tcp->sockfd);
			tcp->sockfd = -1;
		}
		if (tcp->addrinfo_allocated) {
			freeaddrinfo(tcp->addrinfo);
		}
		tcp->addrinfo = NULL;
	}
}

// for Windows compatibility
#include "sockets.h"
int wget_net_init(void)
{
	return gl_sockets_startup(SOCKETS_2_2);
}

int wget_net_deinit(void)
{
	return gl_sockets_cleanup();
}
