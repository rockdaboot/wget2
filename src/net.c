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
 * network routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 16.11.2012               new functions tcp_set_family() and tcp_set_preferred_family()
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>  // on old systems we need this for strcasecmp()...
#include <strings.h> // ...on newer systems we need this
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "xalloc.h"
#include "utils.h"
#include "log.h"
#include "vector.h"
#include "ssl.h"
#include "net.h"

struct TCP {
	void *
		ssl_session;
	int
		sockfd,
		timeout;
	char
		ssl;
};

// global settings
static int
	// timeouts in milliseconds
	// there is no real 'connect timeout', since connects are async
	dns_timeout,
	connect_timeout,
	timeout, // read and write timeouts are the same
	debug,
	family = AF_UNSPEC,
	preferred_family;
static struct addrinfo
	*bind_addrinfo;
static pthread_mutex_t
	dns_mutex = PTHREAD_MUTEX_INITIALIZER;


// resolver / DNS cache entry
struct ADDR_ENTRY {
	const char
		*host,
		*port;
	struct addrinfo
		*addrinfo;
};

// resolver / DNS cache container
static VECTOR
	*dns_cache;

struct addrinfo *tcp_resolve(const char *host, const char *port)
{
	if (dns_cache) {
		struct ADDR_ENTRY *entryp, entry = { .host = host, .port = port };

		pthread_mutex_lock(&dns_mutex);
		entryp = vec_get(dns_cache, vec_find(dns_cache, &entry));
		pthread_mutex_unlock(&dns_mutex);

		if (entryp) {
			// DNS cache entry found
			return entryp->addrinfo;
		}
	}

	// we need a block here to not let fall non-C99 compilers (e.g. gcc 2.95)
	// it doesn't really hurt
	{
		struct addrinfo hints = {
			.ai_family = family,
			.ai_socktype = SOCK_STREAM,
#if defined(AI_ADDRCONFIG)
	#if defined(AI_NUMERICSERV)
			.ai_flags = AI_ADDRCONFIG | (port && isdigit(*port) ? AI_NUMERICSERV : 0)
	#else
			.ai_flags = AI_ADDRCONFIG
	#endif
#elif defined(AI_NUMERICSERV)
			.ai_flags = (port && isdigit(*port) ? AI_NUMERICSERV : 0)
#endif
		};
		struct addrinfo *addrinfo = NULL, *ai;
		int tries, rc = 0;

#if !defined(AI_NUMERICSERV)
		// to make the function work on old systems
		char portbuf[16];

		if (port && !isdigit(port)) {
			if (!strcasecmp(port, "http"))
				port = "80";
			else if (!strcasecmp(port, "https"))
				port = "443";
			else if (!strcasecmp(port, "ftp"))
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

		if (port)
			log_printf("resolving %s:%s...\n", host, port);
		else
			log_printf("resolving %s...\n", host);

		// get the IP address for the server
		for (tries = 0; tries < 3; tries++) {
			if ((rc = getaddrinfo(host, port, &hints, &addrinfo)) == 0 || rc != EAI_AGAIN)
				break;

			{
				const struct timespec ts = {0, 100 * 1000 * 1000};
				nanosleep(&ts, NULL);
			}
		}

		if (rc) {
			if (port)
				err_printf(_("Failed to resolve %s:%s (%s)\n"), host, port, gai_strerror(rc));
			else
				err_printf(_("Failed to resolve %s (%s)\n"), host, gai_strerror(rc));
			return NULL;
		}

		if (family == AF_UNSPEC && preferred_family != AF_UNSPEC) {
			struct addrinfo *preferred = NULL, *preferred_tail = NULL;
			struct addrinfo *unpreferred = NULL, *unpreferred_tail = NULL;

			// split address list into preferred and unpreferred, keeping the original order
			for (ai = addrinfo; ai;) {
				if (ai->ai_family == preferred_family) {
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

		if (debug) {
			for (ai = addrinfo; ai; ai = ai->ai_next) {
				char adr[NI_MAXHOST], sport[NI_MAXSERV];
				int rc;

				if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
					log_printf("has %s:%s\n", adr, sport);
				else
					log_printf("has ???:%s (%s)\n", sport, gai_strerror(rc));
			}
		}

		if (dns_cache) {
			// insert addrinfo into dns cache
			size_t hostlen = strlen(host) + 1;
			size_t portlen = port ? strlen(port) + 1 : 1;
			struct ADDR_ENTRY *entryp = xmalloc(sizeof(struct ADDR_ENTRY) + hostlen + portlen);

			entryp->host = ((char *)entryp) + sizeof(struct ADDR_ENTRY);
			entryp->port = ((char *)entryp) + sizeof(struct ADDR_ENTRY) + hostlen;
			entryp->addrinfo = addrinfo;
			strcpy((char *)entryp->host, host); // ugly cast, but semantically ok
			strcpy((char *)entryp->port, port ? port : ""); // ugly cast, but semantically ok

			pthread_mutex_lock(&dns_mutex);
			if (vec_find(dns_cache, entryp) == -1)
				vec_insert_sorted_noalloc(dns_cache, entryp);
			pthread_mutex_unlock(&dns_mutex);
		}

		return addrinfo;
	}
}

void tcp_set_debug(int _debug)
{
	debug = _debug;
}

void tcp_set_preferred_family(int _family)
{
	preferred_family = _family;
}

void tcp_set_family(int _family)
{
	family = _family;
}

static int PURE NONNULL_ALL compare_addr(struct ADDR_ENTRY *a1, struct ADDR_ENTRY *a2)
{
	int n;

	if ((n = strcasecmp(a1->host, a2->host)) == 0)
		return strcasecmp(a1->port, a2->port);

	return n;
}

void tcp_set_dns_caching(int caching)
{
	pthread_mutex_lock(&dns_mutex);
	if (caching) {
		if (!dns_cache)
			dns_cache = vec_create(4,-2,(int(*)(const void *, const void *))compare_addr);
	} else {
		if (dns_cache) {
			int it;

			for (it = 0; it < vec_size(dns_cache); it++) {
				struct ADDR_ENTRY *entryp = vec_get(dns_cache, it);
				freeaddrinfo(entryp->addrinfo);
			}
			vec_free(&dns_cache);
		}
	}
	pthread_mutex_unlock(&dns_mutex);
}

void tcp_set_dns_timeout(int timeout)
{
	dns_timeout = timeout;
}

void tcp_set_connect_timeout(int _timeout)
{
	connect_timeout = _timeout;
}

void tcp_set_timeout(tcp_t tcp, int _timeout)
{
	if (tcp)
		tcp->timeout = _timeout;
	else
		timeout = _timeout;
}

void tcp_set_bind_address(const char *bind_address)
{
	if (bind_addrinfo) {
		freeaddrinfo(bind_addrinfo);
		bind_addrinfo = NULL;
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
			bind_addrinfo = tcp_resolve(host, s + 1); // bind to specified port
		} else {
			bind_addrinfo = tcp_resolve(host, NULL); // bind to any host
		}
	}
}

tcp_t tcp_connect(struct addrinfo *addrinfo, const char *hostname)
{
	tcp_t tcp = NULL;
	int sockfd = -1, rc;
	char adr[NI_MAXHOST], port[NI_MAXSERV];

	if (debug) {
		if ((rc = getnameinfo(addrinfo->ai_addr, addrinfo->ai_addrlen, adr, sizeof(adr), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
			log_printf("trying %s:%s...\n", adr, port);
		else
			log_printf("trying ???:%s (%s)...\n", port, gai_strerror(rc));
	}

	if ((sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) != -1) {
		int on = 1;

		fcntl(sockfd, F_SETFL, O_NDELAY);

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
			err_printf(_("Failed to set socket option REUSEADDR\n"));

		on = 1;
		if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == -1)
			err_printf(_("Failed to set socket option NODELAY\n"));

		if (bind_addrinfo) {
			if (debug) {
				if ((rc = getnameinfo(bind_addrinfo->ai_addr, bind_addrinfo->ai_addrlen, adr, sizeof(adr), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
					log_printf("binding to %s:%s...\n", adr, port);
				else
					log_printf("binding to ???:%s (%s)...\n", port, gai_strerror(rc));
			}

			if (bind(sockfd, bind_addrinfo->ai_addr, bind_addrinfo->ai_addrlen) != 0) {
				err_printf(_("Failed to bind (%d)\n"), errno);
				close(sockfd);
				return NULL;
			}
		}

		if (connect(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0 &&
			errno != EINPROGRESS)
		{
			err_printf(_("Failed to connect (%d)\n"), errno);
			close(sockfd);
		} else {
			tcp = xcalloc(1, sizeof(*tcp));
			tcp->sockfd = sockfd;
			tcp->timeout = timeout;
			if (hostname) {
				tcp->ssl = 1;
				tcp->ssl_session = ssl_open(tcp->sockfd, hostname, connect_timeout);
				if (!tcp->ssl_session)
					tcp_close(&tcp);
			}
		}
	} else
		err_printf(_("Failed to create socket\n"));

	return tcp;
}

ssize_t tcp_read(tcp_t tcp, char *buf, size_t count)
{
	ssize_t rc;

	if (tcp->ssl) {
		rc = ssl_read_timeout(tcp->ssl_session, buf, count, tcp->timeout);
	} else {
		// 0: no timeout / immediate
		// -1: INFINITE timeout
		if (tcp->timeout) {
			// wait for socket to be ready to read
			struct pollfd pollfd[1] = {
				{ tcp->sockfd, POLLIN, 0}};

			if ((rc = poll(pollfd, 1, tcp->timeout)) <= 0)
				return rc;

			if (!(pollfd[0].revents & POLLIN))
				return -1;
		}

		rc = read(tcp->sockfd, buf, count);
	}

	if (rc < 0)
		err_printf(_("Failed to read %zu bytes (%d)\n"), count, errno);

	return rc;
}

ssize_t tcp_write(tcp_t tcp, const char *buf, size_t count)
{
	ssize_t nwritten = 0, n;
	int rc;

	if (tcp->ssl)
		return ssl_write_timeout(tcp->ssl_session, buf, count, timeout);

	while (count) {
		// 0: no timeout / immediate
		// -1: INFINITE timeout
		if (tcp->timeout) {
			// wait for socket to be ready to write
			struct pollfd pollfd[1] = {
				{ tcp->sockfd, POLLOUT, 0}};

			if ((rc = poll(pollfd, 1, tcp->timeout)) <= 0) {
				err_printf(_("Failed to poll (%d)\n"), errno);
				return rc;
			}

			if (!(pollfd[0].revents & POLLOUT)) {
				err_printf(_("Failed to get POLLOUT event\n"));
				return -1;
			}
		}

		n = write(tcp->sockfd, buf, count);
			
		if (n < 0) {
			err_printf(_("Failed to write %zu bytes (%d)\n"), count, errno);
			return -1;
		}

		if ((size_t)n >= count)
			return nwritten + n;

		count -= n;
		buf += n;
		nwritten += n;
	}

	return 0;
}

ssize_t tcp_send(tcp_t tcp, const char *fmt, ...)
{
	char sbuf[4096], *bufp = NULL;
	ssize_t len, len2 = 0;
	va_list args;

	va_start(args, fmt);
	len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);
	va_end(args);

	if (len >= 0 && len < (ssize_t)sizeof(sbuf)) {
		// message fits into buf - most likely case
		bufp = sbuf;
	} else if (len >= (ssize_t)sizeof(sbuf)) {
		// POSIX compliant or glibc >= 2.1
		bufp = xmalloc(len + 1);

		va_start(args, fmt);
		len = vsnprintf(bufp, len + 1, fmt, args);
		va_end(args);
	} else if (len == -1) {
		// oldstyle with ugly try-and-error fallback (maybe just truncate the msg ?)
		size_t size = sizeof(sbuf);

		do {
			xfree(bufp);
			bufp = xmalloc(size *= 2);
			va_start(args, fmt);
			len = vsnprintf(bufp, size, fmt, args);
			va_end(args);
		} while (len == -1);
	} else {
		err_printf("tcp_send: internal error: unexpected length %zd\n", len);
		return 0;
	}

	len2 = tcp_write(tcp, bufp, len);
	if (len2 > 0)
		log_write(bufp, len2);

	if (bufp != sbuf)
		xfree(bufp);

	if (len2 > 0 && len != len2)
		err_printf("tcp_send: internal error: length mismatch %zd != %zd\n", len, len2);

	return len2;
}

void tcp_close(tcp_t *tcp)
{
	if (tcp && *tcp) {
		if ((*tcp)->sockfd != -1) {
			close((*tcp)->sockfd);
			(*tcp)->sockfd = -1;
		}
		if ((*tcp)->ssl && (*tcp)->ssl_session) {
			ssl_close(&(*tcp)->ssl_session);
		}
		xfree(*tcp);
	}
}
