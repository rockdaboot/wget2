/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
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

#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
//#include <sys/socket.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>  // on old systems we need this for strcasecmp()...
#include <strings.h> // ...on newer systems we need this
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifndef __WIN32
# ifdef __VMS
#  include "vms_ip.h"
# else /* def __VMS */
#  include <netdb.h>
# endif /* def __VMS [else] */
# include <sys/socket.h>
# include <netinet/tcp.h>
# include <netinet/in.h>
# ifndef __BEOS__
#  include <arpa/inet.h>
# endif
#else
# include <winsock2.h>
# include <ws2tcpip.h>
#endif /* not WINDOWS */

#include <libmget.h>
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

static struct mget_tcp_st _global_tcp = {
	.sockfd = -1,
	.dns_timeout = -1,
	.connect_timeout = -1,
	.timeout = -1,
	.family = AF_UNSPEC,
	.caching = 1,
#if defined(TCP_FASTOPEN) && defined(MSG_FASTOPEN)
	.tcp_fastopen = 1,
	.first_send = 1
#endif
};

// resolver / DNS cache container
static mget_vector_t
	*dns_cache;
static mget_thread_mutex_t
	dns_mutex = MGET_THREAD_MUTEX_INITIALIZER;

static struct addrinfo *_mget_dns_cache_get(const char *host, const char *port)
{
	if (dns_cache) {
		struct ADDR_ENTRY *entryp, entry = { .host = host, .port = port };

		mget_thread_mutex_lock(&dns_mutex);
		entryp = mget_vector_get(dns_cache, mget_vector_find(dns_cache, &entry));
		mget_thread_mutex_unlock(&dns_mutex);

		if (entryp) {
			// DNS cache entry found
			return entryp->addrinfo;
		}
	}

	return NULL;
}

static int G_GNUC_MGET_PURE _compare_addr(struct ADDR_ENTRY *a1, struct ADDR_ENTRY *a2)
{
	int n;

	if ((n = strcasecmp(a1->host, a2->host)) == 0)
		return mget_strcasecmp_ascii(a1->port, a2->port);

	return n;
}

static void _free_dns(struct ADDR_ENTRY *entry)
{
	freeaddrinfo(entry->addrinfo);
}

static struct addrinfo * _mget_dns_cache_add(const char *host, const char *port, struct addrinfo *addrinfo)
{
	// insert addrinfo into dns cache
	size_t hostlen = host ? strlen(host) + 1 : 1;
	size_t portlen = port ? strlen(port) + 1 : 1;
	struct ADDR_ENTRY *entryp = xmalloc(sizeof(struct ADDR_ENTRY) + hostlen + portlen);
	int index;

	entryp->host = ((char *)entryp) + sizeof(struct ADDR_ENTRY);
	entryp->port = ((char *)entryp) + sizeof(struct ADDR_ENTRY) + hostlen;
	entryp->addrinfo = addrinfo;
	strcpy((char *)entryp->host, host ? host : ""); // ugly cast, but semantically ok
	strcpy((char *)entryp->port, port ? port : ""); // ugly cast, but semantically ok

	mget_thread_mutex_lock(&dns_mutex);
	if (!dns_cache) {
		dns_cache = mget_vector_create(4, -2, (int(*)(const void *, const void *))_compare_addr);
		mget_vector_set_destructor(dns_cache, (void(*)(void *))_free_dns);
	}

	if ((index = mget_vector_find(dns_cache, entryp)) == -1)
		mget_vector_insert_sorted_noalloc(dns_cache, entryp);
	else {
		// race condition:
		xfree(entryp);
		freeaddrinfo(addrinfo);
		addrinfo = mget_vector_get(dns_cache, index);
	}
	mget_thread_mutex_unlock(&dns_mutex);

	return addrinfo;
}

void mget_dns_cache_free(void)
{
	mget_thread_mutex_lock(&dns_mutex);
	mget_vector_free(&dns_cache);
	mget_thread_mutex_unlock(&dns_mutex);
}

struct addrinfo *mget_tcp_resolve(mget_tcp_t *tcp, const char *host, const char *port)
{
	static mget_thread_mutex_t
		mutex = MGET_THREAD_MUTEX_INITIALIZER;
	struct addrinfo *addrinfo, *ai, hints;
	int tries, rc = 0, ai_flags = 0;

	if (!tcp)
		tcp = &_global_tcp;

//	if (!port)
//		port = "0";

	// if port is NULL,
	if (tcp->caching && port) {
		if ((addrinfo = _mget_dns_cache_get(host, port)))
			return addrinfo;

		// prevent multiple address resolutions of the same host/port
		mget_thread_mutex_lock(&mutex);
		// now try again
		if ((addrinfo = _mget_dns_cache_get(host, port))) {
			mget_thread_mutex_unlock(&mutex);
			return addrinfo;
		}
	}
	addrinfo = NULL;

#if defined(AI_NUMERICSERV)
	ai_flags |= (port && isdigit(*port) ? AI_NUMERICSERV : 0);
#endif
#if defined(AI_ADDRCONFIG)
	ai_flags |= AI_ADDRCONFIG;
#endif

	if (tcp->passive) {
		ai_flags |= AI_PASSIVE;
	}

	memset(&hints, 0 ,sizeof(hints));
	hints.ai_family = tcp->family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = ai_flags;

#if !defined(AI_NUMERICSERV)
	// to make the function work on old systems
	char portbuf[16];

	if (!isdigit(*port)) {
		if (!mget_strcasecmp_ascii(port, "http"))
			port = "80";
		else if (!mget_strcasecmp_ascii(port, "https"))
			port = "443";
		else if (!mget_strcasecmp_ascii(port, "ftp"))
			port = "21";
		else {
			// TODO: check availability of getservbyname_r to use it
			struct servent *s = getservbyname(port, "tcp");
			if (s) {
				snprintf(portbuf, sizeof(portbuf), "%d", s->s_port);
				port = portbuf;
			}
		}
	}
#endif

	debug_printf("resolving %s:%s...\n", host, port);

	// get the IP address for the server
	for (tries = 0; tries < 3; tries++) {
		if ((rc = getaddrinfo(host, port, &hints, &addrinfo)) == 0 || rc != EAI_AGAIN)
			break;

		if (tries < 2)
			mget_millisleep(100);
	}

	if (rc) {
		error_printf(_("Failed to resolve %s:%s (%s)\n"), host, port, gai_strerror(rc));

		if (tcp->caching && port)
			mget_thread_mutex_unlock(&mutex);

		return NULL;
	}

	if (tcp->family == AF_UNSPEC && tcp->preferred_family != AF_UNSPEC) {
		struct addrinfo *preferred = NULL, *preferred_tail = NULL;
		struct addrinfo *unpreferred = NULL, *unpreferred_tail = NULL;

		// split address list into preferred and unpreferred, keeping the original order
		for (ai = addrinfo; ai;) {
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

		// merge preferred + unpreferred
		if (preferred) {
			preferred_tail->ai_next = unpreferred;
			addrinfo = preferred;
		} else {
			addrinfo = unpreferred;
		}
	}

	if (mget_get_logger(MGET_LOGGER_DEBUG)->vprintf) {
		for (ai = addrinfo; ai; ai = ai->ai_next) {
			char adr[NI_MAXHOST], sport[NI_MAXSERV];

			if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
				debug_printf("has %s:%s\n", adr, sport);
			else
				debug_printf("has ???:%s (%s)\n", sport, gai_strerror(rc));
		}
	}

	if (tcp->caching && port) {
		// In case of a race condition the already exisiting addrinfo is returned.
		// The addrinfo argument given to _mget_dns_cache_add() will be freed in this case.
		addrinfo = _mget_dns_cache_add(host, port, addrinfo);
		mget_thread_mutex_unlock(&mutex);
	}

	return addrinfo;
}

static int G_GNUC_MGET_CONST _value_to_family(int value)
{
	switch (value) {
	case MGET_NET_FAMILY_IPV4:
		return AF_INET;
	case MGET_NET_FAMILY_IPV6:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

static int G_GNUC_MGET_CONST _family_to_value(int family)
{
	switch (family) {
	case AF_INET:
		return MGET_NET_FAMILY_IPV4;
	case AF_INET6:
		return MGET_NET_FAMILY_IPV6;
	default:
		return MGET_NET_FAMILY_ANY;
	}
}

void mget_tcp_set_tcp_fastopen(mget_tcp_t *tcp, int tcp_fastopen)
{
#if defined(TCP_FASTOPEN) && defined(MSG_FASTOPEN)
	(tcp ? tcp : &_global_tcp)->tcp_fastopen = tcp_fastopen;
#endif
}

void mget_tcp_set_dns_caching(mget_tcp_t *tcp, int caching)
{
	(tcp ? tcp : &_global_tcp)->caching = caching;
}

int mget_tcp_get_dns_caching(mget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->caching;
}

void mget_tcp_set_protocol(mget_tcp_t *tcp, int protocol)
{
	(tcp ? tcp : &_global_tcp)->protocol = protocol;
}

int mget_tcp_get_protocol(mget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->protocol;
}

void mget_tcp_set_preferred_family(mget_tcp_t *tcp, int family)
{
	(tcp ? tcp : &_global_tcp)->preferred_family = _value_to_family(family);
}

int mget_tcp_get_preferred_family(mget_tcp_t *tcp)
{
	return _family_to_value((tcp ? tcp : &_global_tcp)->preferred_family);
}

void mget_tcp_set_family(mget_tcp_t *tcp, int family)
{
	(tcp ? tcp : &_global_tcp)->family = _value_to_family(family);
}

int mget_tcp_get_family(mget_tcp_t *tcp)
{
	return _family_to_value((tcp ? tcp : &_global_tcp)->family);
}

int mget_tcp_get_local_port(mget_tcp_t *tcp)
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

void mget_tcp_set_dns_timeout(mget_tcp_t *tcp, int timeout)
{
	(tcp ? tcp : &_global_tcp)->dns_timeout = timeout;
}

void mget_tcp_set_connect_timeout(mget_tcp_t *tcp, int timeout)
{
	(tcp ? tcp : &_global_tcp)->connect_timeout = timeout;
}

void mget_tcp_set_timeout(mget_tcp_t *tcp, int timeout)
{
	(tcp ? tcp : &_global_tcp)->timeout = timeout;
}

int mget_tcp_get_timeout(mget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->timeout;
}

void mget_tcp_set_bind_address(mget_tcp_t *tcp, const char *bind_address)
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

		strcpy(copy, bind_address);

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
			tcp->bind_addrinfo = mget_tcp_resolve(tcp, host, s + 1); // bind to host + specified port
		} else {
			tcp->bind_addrinfo = mget_tcp_resolve(tcp, host, NULL); // bind to host on any port
		}
		tcp->bind_addrinfo_allocated = !tcp->caching;
	}
}

void mget_tcp_set_ssl(mget_tcp_t *tcp, int ssl)
{
	(tcp ? tcp : &_global_tcp)->ssl = ssl;
}

int mget_tcp_get_ssl(mget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->ssl;
}

void mget_tcp_set_ssl_hostname(mget_tcp_t *tcp, const char *hostname)
{
	if (!tcp)
		tcp = &_global_tcp;

	xfree(tcp->ssl_hostname);
	tcp->ssl_hostname = mget_strdup(hostname);
}

const char *mget_tcp_get_ssl_hostname(mget_tcp_t *tcp)
{
	return (tcp ? tcp : &_global_tcp)->ssl_hostname;
}

mget_tcp_t *mget_tcp_init(void)
{
	mget_tcp_t *tcp = xmalloc(sizeof(mget_tcp_t));

	*tcp = _global_tcp;
	tcp->ssl_hostname = mget_strdup(_global_tcp.ssl_hostname);

	return tcp;
}

void mget_tcp_deinit(mget_tcp_t **_tcp)
{
	mget_tcp_t *tcp;

	if (!_tcp) {
		xfree(_global_tcp.ssl_hostname);
		return;
	}

	if ((tcp = *_tcp)) {
		mget_tcp_close(tcp);

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
#ifdef WIN32
	unsigned long on = 1;

	if (ioctlsocket(fd, FIONBIO, &on) < 0)
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#elif defined(F_SETFL)
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		error_printf_exit(_("Failed to get socket flags\n"));

	if (fcntl(fd, F_SETFL, flags | O_NDELAY) < 0)
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#else
	int on = 1;

	if (ioctl(fd, FIONBIO, &on) < 0)
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#endif
}

int mget_tcp_ready_2_transfer(mget_tcp_t *tcp, int flags)
{
	return mget_ready_2_transfer(tcp->sockfd, tcp->timeout, flags);
}

int mget_tcp_connect(mget_tcp_t *tcp, const char *host, const char *port)
{
	struct addrinfo *ai;
	int sockfd = -1, rc, ret = MGET_E_UNKNOWN;
	char adr[NI_MAXHOST], s_port[NI_MAXSERV];

	if (tcp->addrinfo_allocated)
		freeaddrinfo(tcp->addrinfo);

	tcp->addrinfo = mget_tcp_resolve(tcp, host, port);
	tcp->addrinfo_allocated = !tcp->caching;

	for (ai = tcp->addrinfo; ai; ai = ai->ai_next) {
		if (mget_get_logger(MGET_LOGGER_DEBUG)->vprintf) {
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
				if (mget_get_logger(MGET_LOGGER_DEBUG)->vprintf) {
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

			if (tcp->ssl)  {
				rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
				tcp->first_send = 0;
			} else {
				if (tcp->tcp_fastopen) {
					rc = 0;
					errno = 0;
					tcp->connect_addrinfo = ai;
				} else {
					rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
					tcp->first_send = 0;
				}
			}

			if (rc < 0
				&& errno != EAGAIN
#ifdef EINPROGRESS
				&& errno != EINPROGRESS
#endif
			) {
				error_printf(_("Failed to connect (%d)\n"), errno);
				ret = MGET_E_CONNECT;
				close(sockfd);
			} else {
				tcp->sockfd = sockfd;
				if (tcp->ssl) {
//					tcp->ssl_session = mget_ssl_open(tcp->sockfd, tcp->ssl_hostname, tcp->connect_timeout);
//					if (!tcp->ssl_session) {
					if ((ret = mget_ssl_open(tcp))) {
						if (ret == MGET_E_CERTIFICATE) {
							mget_tcp_close(tcp);
							break; /* stop here - the server cert couldn't be validated */
						}

						// do not free tcp->addrinfo when calling mget_tcp_close()
						struct addrinfo *ai_tmp = tcp->addrinfo;
						tcp->addrinfo = NULL;
						mget_tcp_close(tcp);
						tcp->addrinfo = ai_tmp;
						continue;
					}
				}

				return MGET_E_SUCCESS;
			}
		} else
			error_printf(_("Failed to create socket (%d)\n"), errno);
	}

	return ret;
}

int mget_tcp_listen(mget_tcp_t *tcp, const char *host, const char *port, int backlog)
{
	struct addrinfo *ai;
	int sockfd = -1, rc;
	char adr[NI_MAXHOST], s_port[NI_MAXSERV];

	if (tcp->bind_addrinfo_allocated)
		freeaddrinfo(tcp->bind_addrinfo);

	tcp->passive = 1;
	tcp->bind_addrinfo = mget_tcp_resolve(tcp, host, port);
	tcp->bind_addrinfo_allocated = !tcp->caching;

	for (ai = tcp->bind_addrinfo; ai; ai = ai->ai_next) {
		if (mget_get_logger(MGET_LOGGER_DEBUG)->vprintf) {
			if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), s_port, sizeof(s_port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
				debug_printf("try to listen on %s:%s...\n", adr, s_port);
			else
				debug_printf("try to listen on %s:%s (%s)...\n", host, s_port, gai_strerror(rc));
		}

		if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) != -1) {
			int on = 1;

			_set_async(sockfd);

			if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
				error_printf(_("Failed to set socket option REUSEADDR\n"));

			on = 1;
			if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
				error_printf(_("Failed to set socket option NODELAY\n"));

#ifdef TCP_FASTOPEN
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

				if (mget_get_logger(MGET_LOGGER_DEBUG)->vprintf) {
					if (!port)
						snprintf(s_port, sizeof(s_port), "%d", mget_tcp_get_local_port(tcp));

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

mget_tcp_t *mget_tcp_accept(mget_tcp_t *parent_tcp)
{
	int sockfd;

	// 0: no timeout / immediate
	// -1: INFINITE timeout
	if (parent_tcp->timeout) {
		if (mget_ready_2_read(parent_tcp->sockfd, parent_tcp->timeout) <= 0)
			return NULL;
	}

	if ((sockfd = accept(parent_tcp->sockfd, parent_tcp->bind_addrinfo->ai_addr, &parent_tcp->bind_addrinfo->ai_addrlen)) != -1) {
		mget_tcp_t *tcp = xmalloc(sizeof(mget_tcp_t));

		*tcp = *parent_tcp;
		tcp->sockfd = sockfd;
		tcp->ssl_hostname = NULL;
		tcp->addrinfo = NULL;
		tcp->bind_addrinfo = NULL;

		if (tcp->ssl) {
			if (mget_tcp_tls_start(tcp))
				mget_tcp_deinit(&tcp);
		}

		return tcp;
	}

	error_printf(_("Failed to accept (%d)\n"), errno);

	return NULL;
}

int mget_tcp_tls_start(mget_tcp_t *tcp)
{
	if (tcp->passive)
		return mget_ssl_server_open(tcp);
	else
		return mget_ssl_open(tcp);
}

void mget_tcp_tls_stop(mget_tcp_t *tcp)
{
	if (tcp->passive)
		mget_ssl_server_close(&tcp->ssl_session);
	else
		mget_ssl_close(&tcp->ssl_session);
}

ssize_t mget_tcp_read(mget_tcp_t *tcp, char *buf, size_t count)
{
	ssize_t rc;

	if (tcp->ssl_session) {
		rc = mget_ssl_read_timeout(tcp->ssl_session, buf, count, tcp->timeout);
	} else {
		// 0: no timeout / immediate
		// -1: INFINITE timeout
		if (tcp->timeout) {
			if ((rc = mget_ready_2_read(tcp->sockfd, tcp->timeout)) <= 0)
				return rc;
		}

		rc = read(tcp->sockfd, buf, count);
	}

	if (rc < 0)
		error_printf(_("Failed to read %zu bytes (%d)\n"), count, errno);

	return rc;
}

ssize_t mget_tcp_write(mget_tcp_t *tcp, const char *buf, size_t count)
{
	ssize_t nwritten = 0, n;
	int rc;

	if (tcp->ssl_session)
		return mget_ssl_write_timeout(tcp->ssl_session, buf, count, tcp->timeout);

	while (count) {
#ifdef MSG_FASTOPEN
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
#ifdef EINPROGRESS
					&& errno != EINPROGRESS
#endif
			) {
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
#ifdef EINPROGRESS
				&& errno != EINPROGRESS
#endif
			) {
				error_printf(_("Failed to write %zu bytes (%d)\n"), count, errno);
				return -1;
			}

			// 0: no timeout / immediate
			// -1: INFINITE timeout
			if (tcp->timeout) {
				if ((rc = mget_ready_2_write(tcp->sockfd, tcp->timeout)) <= 0)
					return rc;
			}
		}
	}

	return 0;
}

ssize_t mget_tcp_vprintf(mget_tcp_t *tcp, const char *fmt, va_list args)
{
	char sbuf[4096];
	mget_buffer_t buf;
	ssize_t len2;

	mget_buffer_init(&buf, sbuf, sizeof(sbuf));
	mget_buffer_vprintf2(&buf, fmt, args);

	len2 = mget_tcp_write(tcp, buf.data, buf.length);

	mget_buffer_deinit(&buf);

	if (len2 > 0)
		debug_write(buf.data, len2);

	if (len2 > 0 && (ssize_t) buf.length != len2)
		error_printf("tcp_send: internal error: length mismatch %zu != %zd\n", buf.length, len2);

	return len2;
}

ssize_t mget_tcp_printf(mget_tcp_t *tcp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ssize_t len = mget_tcp_vprintf(tcp, fmt, args);
	va_end(args);

	return len;
}

void mget_tcp_close(mget_tcp_t *tcp)
{
	if (tcp) {
		mget_tcp_tls_stop(tcp);
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
