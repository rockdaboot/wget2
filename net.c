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
 *
 */

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

//#include "options.h"
#include "xalloc.h"
#include "utils.h"
#include "options.h"
#include "log.h"
#include "net.h"

struct TCP {
	int
		sockfd,
		timeout;
};

struct addrinfo *tcp_resolve(const char *host, const char *port)
{
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
#if defined(AI_ADDRCONFIG)
	#if defined(AI_NUMERICSERV)
		.ai_flags = AI_ADDRCONFIG | (isdigit(*port) ? AI_NUMERICSERV : 0)
	#else
		.ai_flags = AI_ADDRCONFIG
	#endif
#elif defined(AI_NUMERICSERV)
		.ai_flags = (isdigit(*port) ? AI_NUMERICSERV : 0)
#endif
	};
	struct addrinfo *addrinfo = NULL, *ai;
	int tries, rc = 0;

#if !defined(AI_NUMERICSERV)
	// to make the function work on old systems
	char portbuf[16];

	if (!isdigit(port)) {
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

	log_printf("resolve %s:%s...\n", host, port);

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
		err_printf(_("Failed to resolve %s:%s (%s)\n"), host, port, gai_strerror(rc));
		return NULL;
	} else {
		if (config.debug) {
			for (ai = addrinfo; ai; ai = ai->ai_next) {
				char adr[NI_MAXHOST], sport[NI_MAXSERV];
				int rc;

				if ((rc = getnameinfo(ai->ai_addr, ai->ai_addrlen, adr, sizeof(adr), sport, sizeof(sport), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
					log_printf("has %s:%s\n", adr, sport);
				else
					log_printf("has ???:%s (%s)\n", sport, gai_strerror(rc));
			}
		}

		return addrinfo;
	}
}

void tcp_set_timeout(tcp_t tcp, int timeout)
{
	if (tcp)
		tcp->timeout = timeout;
}

tcp_t tcp_connect(struct addrinfo *addrinfo)
{
	tcp_t tcp = NULL;
	int sockfd = -1, rc;
	char adr[NI_MAXHOST], port[NI_MAXSERV];

	if ((rc = getnameinfo(addrinfo->ai_addr, addrinfo->ai_addrlen, adr, sizeof(adr), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)) == 0)
		log_printf("trying %s:%s...\n", adr, port);
	else
		log_printf("trying ???:%s (%s)...\n", port, gai_strerror(rc));

	if ((sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol)) != -1) {
		int on = 1;

		fcntl(sockfd, F_SETFL, O_NDELAY);

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
			err_printf(_("Failed to set socket option REUSEADDR\n"));

		on = 1;
		if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == -1)
			err_printf(_("Failed to set socket option NODELAY\n"));

		if (connect(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0 &&
			errno != EINPROGRESS) {
			err_printf(_("Failed to connect (%d)\n"), errno);
			close(sockfd);
		} else {
			tcp = xcalloc(1, sizeof(*tcp));
			tcp->sockfd = sockfd;
		}
	} else
		err_printf(_("Failed to create socket\n"));

	return tcp;
}

ssize_t tcp_read(tcp_t tcp, char *buf, size_t count)
{
	ssize_t rc;

	if (tcp->timeout) {
		struct pollfd pollfd[1] = {
			{ tcp->sockfd, POLLIN, 0}};

		if ((rc = poll(pollfd, 1, tcp->timeout)) < 1)
			return rc;

		if (!(pollfd[0].revents & POLLIN))
			return -1;
	}

	rc = read(tcp->sockfd, buf, count);
	if (rc == -1)
		err_printf(_("Failed to read (%d)\n"), errno);

	return rc;
}

ssize_t tcp_write(tcp_t tcp, const char *buf, size_t count)
{
	struct pollfd pollfd[1] = {
		{ tcp->sockfd, POLLOUT, 0}};
	ssize_t nwritten = 0, n;
	int rc;

	while (count) {
		if (tcp->timeout) {
			if ((rc = poll(pollfd, 1, tcp->timeout)) < 1) {
				err_printf(_("Failed to poll (%d)\n"), errno);
				return rc;
			}

			if (!(pollfd[0].revents & POLLOUT)) {
				err_printf(_("Failed to get POLLOUT event\n"));
				return -1;
			}
		}

		if ((n = write(tcp->sockfd, buf, count)) == -1) {
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
	int len;
	ssize_t len2 = 0;
	va_list args;

	va_start(args, fmt);
	len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);
	va_end(args);

	if (len >= 0 && len < (int)sizeof(sbuf)) {
		// message fits into buf - most likely case
		bufp = sbuf;
	} else if (len >= (int)sizeof(sbuf)) {
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
	}

	len2 = tcp_write(tcp, bufp, len);
	if (len2 > 0)
		log_write(bufp, len2);

	if (bufp != sbuf)
		xfree(bufp);

	if (len2 > 0 && len != len2)
		err_printf("tcp_send: internal error: length mismatch %d != %zd\n", len, len2);

	return len2;
}

void tcp_close(tcp_t *tcp)
{
	if (tcp && *tcp) {
		if ((*tcp)->sockfd != -1) {
			close((*tcp)->sockfd);
			(*tcp)->sockfd = -1;
		}
		xfree(*tcp);
	}
}
