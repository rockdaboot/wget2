/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Options and related routines
 *
 * Changelog
 * 12.06.2012  Tim Ruehsen  created
 *
 *
 * How to add a new command line option
 * ====================================
 * - extend option.h/struct config with the needed variable
 * - add a default value for your variable in the 'config' initializer if needed (in this file)
 * - add the long option into 'options[]' (in this file). keep alphabetical order !
 * - if appropriate, add a new parse function (examples see below)
 * - extend the print_help() function and the documentation
 *
 * First, I prepared the parsing to allow multiple arguments for an option,
 * e.g. "--whatever arg1 arg2 ...".
 * But now I think, it is ok to say 'each option may just have 0 or 1 option'.
 * An option with a list of values might then look like: --whatever="arg1 arg2 arg3" or use
 * any other argument separator. I remove the legacy code as soon as I am 100% sure...
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <c-ctype.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
//#include <netdb.h>

#include <libwget.h>

#include "wget.h"
#include "log.h"
#include "options.h"

typedef const struct option *option_t; // forward declaration

struct option {
	const char
		*long_name;
	void
		*var;
	int
		(*parser)(option_t opt, const char *val);
	int
		args;
	char
		short_name;
};

static int G_GNUC_WGET_NORETURN print_help(G_GNUC_WGET_UNUSED option_t opt, G_GNUC_WGET_UNUSED const char *val)
{
	puts(
		"Wget V" PACKAGE_VERSION " - multithreaded metalink/file/website downloader written in C\n"
		"\n"
		"Usage: wget [options...] <url>...\n"
		"\n"
		"Startup:\n"
		"  -V  --version           Display the version of Wget and exit.\n"
		"  -h  --help              Print this help.\n"
		"  -v  --verbose           Print more messages. (default: on)\n"
		"  -q  --quiet             Print no messages except debugging messages. (default: off)\n"
		"  -d  --debug             Print debugging messages. (default: off)\n"
		"      --config-file       Path to a wgetrc file.\n"
		"  -o  --output-file       File where messages are printed to, '-' for STDOUT.\n"
		"  -a  --append-output     File where messages are appended to, '-' for STDOUT.\n"
		"  -i  --input-file        File where URLs are read from, - for STDIN.\n"
		"      --input-encoding    Character encoding of the file contents read with --input-file. (default: local encoding)\n"
		"  -F  --force-html        Treat input file as HTML. (default: off)\n"
		"      --force-css         Treat input file as CSS. (default: off) (NEW!)\n"
		"      --force-sitemap     Treat input file as Sitemap. (default: off) (NEW!)\n"
		"      --force-atom        Treat input file as Atom Feed. (default: off) (NEW!)\n"
		"      --force-rss         Treat input file as RSS Feed. (default: off) (NEW!)\n"
		"      --force-metalink    Treat input file as Metalink. (default: off) (NEW!)\n"
		"  -B  --base              Base for relative URLs read from input-file or from command line\n"
		"  -e  --execute           Wget compatibility option, not needed for Wget\n"
		"      --fsync-policy      Use fsync() to wait for data being written to the pysical layer. (default: off) (NEW!)\n"
		"\n");
	puts(
		"Download:\n"
		"  -r  --recursive         Recursive download. (default: off)\n"
		"  -H  --span-hosts        Span hosts that were not given on the command line. (default: off)\n"
		"      --max-threads       Max. concurrent download threads. (default: 5) (NEW!)\n"
		"      --max-redirect      Max. number of redirections to follow. (default: 20)\n"
		"  -T  --timeout           General network timeout in seconds.\n"
		"      --dns-timeout       DNS lookup timeout in seconds.\n"
		"      --connect-timeout   Connect timeout in seconds.\n"
		"      --read-timeout      Read and write timeout in seconds.\n"
		"  -O  --output-document   File where downloaded content is written to, '-'  for STDOUT.\n"
		"      --spider            Enable web spider mode. (default: off)\n"
		"      --proxy             Enable support for *_proxy environment variables. (default: on)\n"
		"      --http-proxy        Set HTTP proxy/proxies, overriding environment variables.\n"
		"                          Use comma to separate proxies\n"
		"      --https-proxy       Set HTTPS proxy/proxies, overriding environment variables.\n"
		"                          Use comma to separate proxies\n"
		"  -S  --server-response   Print the server response headers. (default: off)\n"
		"  -c  --continue-download Continue download for given files. (default: off)\n"
		"      --use-server-timestamps Set local file's timestamp to server's timestamp. (default: on)\n"
		"  -N  --timestamping      Just retrieve younger files than the local ones. (default: off)\n"
		"      --strict-comments   A dummy option. Parsing always works non-strict.\n"
		"      --delete-after      Don't save downloaded files. (default: off)\n"
		"  -4  --inet4-only        Use IPv4 connections only. (default: off)\n"
		"  -6  --inet6-only        Use IPv6 connections only. (default: off)\n"
		"      --prefer-family     Prefer IPv4 or IPv6. (default: none)\n"
		"      --cache             Enabled using of server cache. (default: on)\n"
		"      --clobber           Enable file clobbering. (default: on)\n"
		"      --bind-address      Bind to sockets to local address. (default: automatic)\n"
		"  -D  --domains           Comma-separated list of domains to follow.\n"
		"      --exclude-domains   Comma-separated list of domains NOT to follow.\n"
		"      --user              Username for Authentication. (default: empty username)\n"
		"      --password          Password for Authentication. (default: empty password)\n"
		"  -l  --level             Maximum recursion depth. (default: 5)\n"
		"  -p  --page-requisites   Download all necessary files to display a HTML page\n"
		"      --parent            Ascend above parent directory. (default: on)\n"
		"      --trust-server-names  On redirection use the server's filename. (default: off)\n"
		"      --chunk-size        Download large files in multithreaded chunks. (default: 0 (=off))\n"
		"                          Example: wget --chunk-size=1M\n");
	puts(
		"      --progress          Type of progress bar (bar, dot, none). (default: none)\n"
		"      --local-encoding    Character encoding of environment and filenames.\n"
		"      --remote-encoding   Character encoding of remote files (if not specified in Content-Type HTTP header or in document itself)\n"
		"  -t  --tries             Number of tries for each download. (default 20)\n"
		"  -A  --accept            Comma-separated list of file name suffixes or patterns.\n"
		"  -R  --reject            Comma-separated list of file name suffixes or patterns.\n"
		"      --ignore-case       Ignore case when matching files. (default: off)\n"
		"  -k  --convert-links     Convert embedded URLs to local URLs. (default: off)\n"
		"  -K  --backup-converted  When converting, keep the original file with a .orig suffix. (default: off)\n"
		"  -w  --wait              Wait number of seconds between downloads (per thread). (default: 0)\n"
		"      --waitretry         Wait up to number of seconds after error (per thread). (default: 10)\n"
		"      --random-wait       Wait 0.5 up to 1.5*<--wait> seconds between downloads (per thread). (default: off)\n"
		"      --dns-caching       Caching of domain name lookups. (default: on)\n"
		"      --tcp-fastopen      Enable TCP Fast Open (TFO). (default: on)\n"
		"      --iri               Wget dummy option, you can't switch off international support\n"
		"      --robots            Respect robots.txt standard for recursive downloads. (default: on)\n"
		"      --restrict-file-names  unix, windows, nocontrol, ascii, lowercase, uppercase, none\n"
		"  -m  --mirror            Turn on mirroring options -r -N -l inf\n"
		"      --follow-tags       Scan additional tag/attributes for URLs, e.g. --follow-tags=\"img/data-500px,img/data-hires\n"
		"      --ignore-tags       Ignore tag/attributes for URL scanning, e.g. --ignore-tags=\"img,a/href\n"
		"      --backups           Make backups instead of overwriting/increasing number. (default: 0)\n"
		"      --post-data         Data to be sent in a POST request.\n"
		"      --post-file         File with data to be sent in a POST request.\n"
		"      --netrc             Load credentials from ~/.netrc if not given. (default: on)\n"
		"      --content-on-error  Save response body even on error status. (default: off)\n"
		"\n");
	puts(
		"HTTP related options:\n"
		"  -U  --user-agent        Set User-Agent: header in requests.\n"
		"      --cookies           Enable use of cookies. (default: on)\n"
		"      --keep-session-cookies  Also save session cookies. (default: off)\n"
		"      --load-cookies      Load cookies from file.\n"
		"      --save-cookies      Save cookies from file.\n"
		"      --cookie-suffixes   Load public suffixes from file. They prevent 'supercookie' vulnerabilities.\n"
		"                          Download the list with:\n"
		"                          wget -O suffixes.txt http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1\n"
		"      --http-keep-alive   Keep connection open for further requests. (default: on)\n"
		"      --save-headers      Save the response headers in front of the response data. (default: off)\n"
		"      --referer           Include Referer: url in HTTP requets. (default: off)\n"
		"  -E  --adjust-extension  Append extension to saved file (.html or .css). (default: off)\n"
		/* For Wget compatibility we also understand --html-extension */
		"      --default-page      Default file name. (default: index.html)\n"
		"  -Q  --quota             Download quota, 0 = no quota. (default: 0)\n"
		"      --http-user         Username for HTTP Authentication. (default: empty username)\n"
		"      --http-password     Password for HTTP Authentication. (default: empty password)\n"
		"      --content-disposition  Take filename from Content-Disposition. (default: off)\n"
		"      --default-page      Default file name if name isn't known. (default: index.html)\n"
		"      --netrc-file        Set file for login/password to use instead of ~/.netrc. (default: ~/.netrc)\n"
		"      --metalink          Follow a metalink file instead of storing it (default: on)\n"
		"\n");
	puts(
		"HTTPS (SSL/TLS) related options:\n"
		"      --secure-protocol   Set protocol to be used (auto, SSLv3, TLSv1, PFS). (default: auto)\n"
		"                          Or use GnuTLS priority strings, e.g. NORMAL:-VERS-SSL3.0:-RSA\n"
		"      --check-certificate Check the server's certificate. (default: on)\n"
		"      --check-hostname    Check the server's certificate's hostname. (default: on)\n"
		"      --certificate       File with client certificate.\n"
		"      --certificate-type  Certificate type: PEM or DER (known as ASN1). (default: PEM)\n"
		"      --private-key       File with private key.\n"
		"      --private-key-type  Type of the private key (PEM or DER). (default: PEM)\n"
		"      --ca-certificate    File with bundle of PEM CA certificates.\n"
		"      --ca-directory      Directory with PEM CA certificates.\n"
		"      --crl-file          File with PEM CRL certificates.\n"
		"      --random-file       File to be used as source of random data.\n"
		"      --egd-file          File to be used as socket for random data from Entropy Gathering Daemon.\n"
		"      --https-only        Do not follow non-secure URLs. (default: off).\n"
		"      --hsts              Use HTTP Strict Transport Security (HSTS). (default: on)\n"
		"      --hsts-file         Set file for HSTS caching. (default: ~/.wget-hsts)\n"
		"      --gnutls-options    Custom GnuTLS priority string. Interferes with --secure-protocol. (default: none)\n"
		"      --ocsp-stapling     Use OCSP stapling to verify the server's certificate. (default: on)\n"
		"      --ocsp              Use OCSP server access to verify server's certificate. (default: on)\n"
		"      --ocsp-file         Set file for OCSP chaching. (default: ~/.wget-ocsp)\n"
		"      --http2             Use HTTP/2 protocol if possible. (default: on)\n"
		"      --tls-false-start   Enable TLS False Start (needs GnuTLS 3.5+). (default: on)"
		"      --tls-resume        Enable TLS Session Resumption. (default: on)"
		"      --tls-session-file  Set file for TLS Session caching. (default: ~/.wget-session)\n"
		"\n");
	puts(
		"Directory options:\n"
		"      --directories       Create hierarchy of directories when retrieving recursively. (default: on)\n"
		"  -x  --force-directories Create hierarchy of directories when not retrieving recursively. (default: off)\n"
		"      --host-directories  Create host directories when retrieving recursively. (default: on)\n"
		"      --protocol-directories  Force creating protocol directories. (default: off)\n"
		"      --cut-dirs          Skip creating given number of directory components. (default: 0)\n"
		"  -P  --directory-prefix  Set directory prefix.\n"
		"\n"
		"Example boolean option: --quiet=no is the same as --no-quiet or --quiet=off or --quiet off\n"
		"Example string option: --user-agent=SpecialAgent/1.3.5 or --user-agent \"SpecialAgent/1.3.5\"\n"
		"\n"
		"To reset string options use --[no-]option\n"
		"\n");

/*
 * -a / --append-output should be reduced to -o (with always appending to logfile)
 * Using rm logfile + wget achieves the old behaviour...
 *
 */
	exit(0);
}

static int parse_integer(option_t opt, const char *val)
{
	*((int *)opt->var) = val ? atoi(val) : 0;

	return 0;
}

static int parse_numbytes(option_t opt, const char *val)
{
	if (val) {
		char modifier = 0, error = 0;
		double num = 0;

		if (!wget_strcasecmp_ascii(val, "INF") || !wget_strcasecmp_ascii(val, "INFINITY")) {
			*((long long *)opt->var) = 0;
			return 0;
		}

		if (sscanf(val, " %lf%c", &num, &modifier) >= 1) {
			if (modifier) {
				switch (c_tolower(modifier)) {
				case 'k': num *= 1024; break;
				case 'm': num *= 1024*1024; break;
				case 'g': num *= 1024*1024*1024; break;
				case 't': num *= 1024*1024*1024*1024LL; break;
				default: error = 1;
				}
			}
		} else
			error = 1;

		if (!error)
			*((long long *)opt->var) = (long long)num;
		else
			error_printf_exit(_("Invalid byte specifier: %s\n"), val);
	}

	return 0;
}

static int parse_string(option_t opt, const char *val)
{
	// the strdup'ed string will be released on program exit
	xfree(*((const char **)opt->var));
	*((const char **)opt->var) = val ? strdup(val) : NULL;

	return 0;
}

static int parse_stringset(option_t opt, const char *val)
{
	wget_stringmap_t *map = *((wget_stringmap_t **)opt->var);

	if (val) {
		const char *s, *p;

		for (s = val; (p = strchr(s, ',')); s = p + 1) {
			if (p != s)
				wget_stringmap_put_noalloc(map, wget_strmemdup(s, p - s), NULL);
		}
		if (*s)
			wget_stringmap_put_noalloc(map, strdup(s), NULL);
	} else {
		wget_stringmap_clear(map);
	}

	return 0;
}

static int parse_stringlist(option_t opt, const char *val)
{
	wget_vector_t *v = *((wget_vector_t **)opt->var);

	if (val && *val) {
		const char *s, *p;

		if (!v)
			v = *((wget_vector_t **)opt->var) = wget_vector_create(8, -2, (int (*)(const void *, const void *))strcmp);

		for (s = val; (p = strchr(s, ',')); s = p + 1) {
			if (p != s) {
				const char *entry = wget_strmemdup(s, p - s);

				if (wget_vector_find(v, entry) == -1)
					wget_vector_add_noalloc(v, entry);
				else
					xfree(entry);
			}
		}
		if (*s) {
			const char *entry = strdup(s);

			if (wget_vector_find(v, entry) == -1)
				wget_vector_add_noalloc(v, entry);
			else
				xfree(entry);
		}
	} else {
		wget_vector_free(&v);
	}

	return 0;
}

static void _free_tag(wget_html_tag_t *tag)
{
	if (tag) {
		xfree(tag->attribute);
		xfree(tag->name);
	}
}

static void G_GNUC_WGET_NONNULL_ALL _add_tag(wget_vector_t *v, const char *begin, const char *end)
{
	wget_html_tag_t tag;
	const char *attribute;

	if ((attribute = memchr(begin, '/', end - begin))) {
		tag.name = wget_strmemdup(begin, attribute - begin);
		tag.attribute = wget_strmemdup(attribute + 1, (end - begin) - (attribute - begin) - 1);
	} else {
		tag.name = wget_strmemdup(begin, end - begin);
		tag.attribute = NULL;
	}

	if (wget_vector_find(v, &tag) == -1)
		wget_vector_insert_sorted(v, &tag, sizeof(tag));
	else
		_free_tag(&tag); // avoid double entries
}

static int G_GNUC_WGET_NONNULL_ALL _compare_tag(const wget_html_tag_t *t1, const wget_html_tag_t *t2)
{
	int n;

	if (!(n = wget_strcasecmp_ascii(t1->name, t2->name))) {
		if (!t1->attribute) {
			if (!t2->attribute)
				n = 0;
			else
				n = -1;
		} else if (!t2->attribute) {
			n = 1;
		} else
			n = wget_strcasecmp_ascii(t1->attribute, t2->attribute);
	}

	return n;
}

static int parse_taglist(option_t opt, const char *val)
{
	wget_vector_t *v = *((wget_vector_t **)opt->var);

	if (val && *val) {
		const char *s, *p;

		if (!v) {
			v = *((wget_vector_t **)opt->var) = wget_vector_create(8, -2, (int(*)(const void *, const void *))_compare_tag);
			wget_vector_set_destructor(v, (void(*)(void *))_free_tag);
		}

		for (s = val; (p = strchr(s, ',')); s = p + 1) {
			if (p != s)
				_add_tag(v, s, p);
		}
		if (*s)
			_add_tag(v, s, s + strlen(s));
	} else {
		wget_vector_free(&v);
	}

	return 0;
}

static int parse_bool(option_t opt, const char *val)
{
	if (opt->var) {
		if (!val)
			*((char *) opt->var) = 1;
		else if (!strcmp(val, "1") || !wget_strcasecmp_ascii(val, "y") || !wget_strcasecmp_ascii(val, "yes") || !wget_strcasecmp_ascii(val, "on"))
			*((char *) opt->var) = 1;
		else if (!strcmp(val, "0") || !wget_strcasecmp_ascii(val, "n") || !wget_strcasecmp_ascii(val, "no") || !wget_strcasecmp_ascii(val, "off"))
			*((char *) opt->var) = 0;
		else {
			error_printf(_("Boolean value '%s' not recognized\n"), val);
		}
	}

	return 0;
}

static int parse_mirror(option_t opt, const char *val)
{
	parse_bool(opt, val);

	if (config.mirror) {
		config.recursive = 1;
		config.level = 0; // INF
		config.timestamping = 1;
	} else {
		config.recursive = 0;
		config.level = 5; // default value
		config.timestamping = 0;
	}

	return 0;
}

static int parse_timeout(option_t opt, const char *val)
{
	double fval;

	if (!wget_strcasecmp_ascii(val, "INF") || !wget_strcasecmp_ascii(val, "INFINITY"))
		fval = -1;
	else {
		char modifier = 0;

		if (sscanf(val, " %lf%c", &fval, &modifier) >= 1 && fval > 0) {
			if (modifier) {
				switch (tolower(modifier)) {
				case 's': fval *= 1000; break;
				case 'm': fval *= 60 * 1000; break;
				case 'h': fval *= 60 * 60 * 1000; break;
				case 'd': fval *= 60 * 60 * 24 * 1000; break;
				default: error_printf_exit(_("Invalid time specifier in '%s'\n"), val);
				}
			} else
				fval *= 1000;
		}
	}

	if (fval <= 0) // special Wget compatibility: timeout 0 means INFINITY
		fval = -1;

	if (opt->var) {
		*((int *)opt->var) = (int) fval;
		// debug_printf("timeout set to %gs\n",*((int *)opt->var)/1000.);
	} else {
		// --timeout option sets all timeouts
		config.connect_timeout =
		config.dns_timeout =
		config.read_timeout = (int) fval;
	}

	return 0;
}

static int G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL((1)) parse_cert_type(option_t opt, const char *val)
{
	if (!val || !wget_strcasecmp_ascii(val, "PEM"))
		*((char *)opt->var) = WGET_SSL_X509_FMT_PEM;
	else if (!wget_strcasecmp_ascii(val, "DER") || !wget_strcasecmp_ascii(val, "ASN1"))
		*((char *)opt->var) = WGET_SSL_X509_FMT_DER;
	else
		error_printf_exit("Unknown cert type '%s'\n", val);

	return 0;
}

static int G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL((1)) parse_progress_type(option_t opt, const char *val)
{
	if (!val || !*val || !wget_strcasecmp_ascii(val, "none"))
		*((char *)opt->var) = 0;
	else if (!wget_strcasecmp_ascii(val, "bar"))
		*((char *)opt->var) = 1;
	else
		error_printf_exit("Unknown progress type '%s'\n", val);

	return 0;
}

// legacy option, needed to succeed test suite
static int G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL((1)) parse_restrict_names(option_t opt, const char *val)
{
	if (!val || !*val || !wget_strcasecmp_ascii(val, "none"))
		*((int *)opt->var) = RESTRICT_NAMES_NONE;
	else if (!wget_strcasecmp_ascii(val, "unix"))
		*((int *)opt->var) = RESTRICT_NAMES_UNIX;
	else if (!wget_strcasecmp_ascii(val, "windows"))
		*((int *)opt->var) = RESTRICT_NAMES_WINDOWS;
	else if (!wget_strcasecmp_ascii(val, "nocontrol"))
		*((int *)opt->var) = RESTRICT_NAMES_NOCONTROL;
	else if (!wget_strcasecmp_ascii(val, "ascii"))
		*((int *)opt->var) = RESTRICT_NAMES_ASCII;
	else if (!wget_strcasecmp_ascii(val, "uppercase"))
		*((int *)opt->var) = RESTRICT_NAMES_UPPERCASE;
	else if (!wget_strcasecmp_ascii(val, "lowercase"))
		*((int *)opt->var) = RESTRICT_NAMES_LOWERCASE;
	else
		error_printf_exit("Unknown restrict-file-name type '%s'\n", val);

	return 0;
}

// Wget compatibility: support -nv, -nc, -nd, -nH and -np
// Wget supports --no-... to all boolean and string options
static int parse_n_option(G_GNUC_WGET_UNUSED option_t opt, const char *val)
{
	if (val) {
		const char *p;

		for (p = val; *p; p++) {
			switch (*p) {
			case 'v':
				config.verbose = 0;
				break;
			case 'c':
				config.clobber = 0;
				break;
			case 'd':
				config.directories = 0;
				break;
			case 'H':
				config.host_directories = 0;
				break;
			case 'p':
				config.parent = 0;
				break;
			default:
				error_printf_exit(_("Unknown option '-n%c'\n"), *p);
			}

			debug_printf("name=-n%c value=0\n", *p);
		}
	}

	return 0;
}

static int parse_prefer_family(option_t opt, const char *val)
{
	if (!val || !wget_strcasecmp_ascii(val, "none"))
		*((char *)opt->var) = WGET_NET_FAMILY_ANY;
	else if (!wget_strcasecmp_ascii(val, "ipv4"))
		*((char *)opt->var) = WGET_NET_FAMILY_IPV4;
	else if (!wget_strcasecmp_ascii(val, "ipv6"))
		*((char *)opt->var) = WGET_NET_FAMILY_IPV6;
	else
		error_printf_exit("Unknown address family '%s'\n", val);

	return 0;
}

// default values for config options (if not 0 or NULL)
struct config config = {
	.connect_timeout = -1,
	.dns_timeout = -1,
	.read_timeout = -1,
	.max_redirect = 20,
	.max_threads = 5,
	.num_threads = 1,
	.dns_caching = 1,
	.tcp_fastopen = 1,
	.user_agent = PACKAGE_NAME"/"PACKAGE_VERSION,
	.verbose = 1,
	.check_certificate=1,
	.check_hostname=1,
	.cert_type = WGET_SSL_X509_FMT_PEM,
	.private_key_type = WGET_SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system",
	.cookies = 1,
	.keep_alive = 1,
	.use_server_timestamps = 1,
	.directories = 1,
	.host_directories = 1,
	.cache = 1,
	.clobber = 1,
	.default_page = "index.html",
	.level = 5,
	.parent = 1,
	.robots = 1,
	.tries = 20,
	.hsts = 1,
#if defined WITH_LIBNGHTTP2
	.http2 = 1,
	.http2_request_window = 30,
	.http1_request_window = 10,
#endif
	.ocsp = 1,
	.ocsp_stapling = 1,
	.netrc = 1,
	.waitretry = 10 * 1000,
	.metalink = 1,
	.tls_false_start = 1,
	.tls_resume = 1,
};

static int parse_execute(option_t opt, const char *val);

static const struct option options[] = {
	// long name, config variable, parse function, number of arguments, short name
	// leave the entries in alphabetical order of 'long_name' !
	{ "accept", &config.accept_patterns, parse_stringlist, 1, 'A' },
	{ "adjust-extension", &config.adjust_extension, parse_bool, 0, 'E' },
	{ "append-output", &config.logfile_append, parse_string, 1, 'a' },
	{ "backup-converted", &config.backup_converted, parse_bool, 0, 'K' },
	{ "backups", &config.backups, parse_integer, 0, 0 },
	{ "base", &config.base_url, parse_string, 1, 'B' },
	{ "bind-address", &config.bind_address, parse_string, 1, 0 },
	{ "ca-certificate", &config.ca_cert, parse_string, 1, 0 },
	{ "ca-directory", &config.ca_directory, parse_string, 1, 0 },
	{ "cache", &config.cache, parse_bool, 0, 0 },
	{ "certificate", &config.cert_file, parse_string, 1, 0 },
	{ "certificate-type", &config.cert_type, parse_cert_type, 1, 0 },
	{ "check-certificate", &config.check_certificate, parse_bool, 0, 0 },
	{ "check-hostname", &config.check_hostname, parse_bool, 0, 0 },
	{ "chunk-size", &config.chunk_size, parse_numbytes, 1, 0 },
	{ "clobber", &config.clobber, parse_bool, 0, 0 },
	{ "config", &config.config_file, parse_string, 1, 0}, // for backward compatibility only
	{ "config-file", &config.config_file, parse_string, 1, 0},
	{ "connect-timeout", &config.connect_timeout, parse_timeout, 1, 0 },
	{ "content-disposition", &config.content_disposition, parse_bool, 0, 0 },
	{ "content-on-error", &config.content_on_error, parse_bool, 0, 0 },
	{ "continue", &config.continue_download, parse_bool, 0, 'c' },
	{ "convert-links", &config.convert_links, parse_bool, 0, 'k' },
	{ "cookie-suffixes", &config.cookie_suffixes, parse_string, 1, 0 },
	{ "cookies", &config.cookies, parse_bool, 0, 0 },
	{ "crl-file", &config.crl_file, parse_string, 1, 0 },
	{ "cut-dirs", &config.cut_directories, parse_integer, 1, 0 },
	{ "debug", &config.debug, parse_bool, 0, 'd' },
	{ "default-page", &config.default_page, parse_string, 1, 0 },
	{ "delete-after", &config.delete_after, parse_bool, 0, 0 },
	{ "directories", &config.directories, parse_bool, 0, 0 },
	{ "directory-prefix", &config.directory_prefix, parse_string, 1, 'P' },
	{ "dns-caching", &config.dns_caching, parse_bool, 0, 0 },
	{ "dns-timeout", &config.dns_timeout, parse_timeout, 1, 0 },
	{ "domains", &config.domains, parse_stringlist, 1, 'D' },
	{ "egd-file", &config.egd_file, parse_string, 1, 0 },
	{ "exclude-domains", &config.exclude_domains, parse_stringlist, 1, 0 },
	{ "execute", NULL, parse_execute, 1, 'e' },
	{ "follow-tags", &config.follow_tags, parse_taglist, 1, 0 },
	{ "force-atom", &config.force_atom, parse_bool, 0, 0 },
	{ "force-css", &config.force_css, parse_bool, 0, 0 },
	{ "force-directories", &config.force_directories, parse_bool, 0, 'x' },
	{ "force-html", &config.force_html, parse_bool, 0, 'F' },
	{ "force-metalink", &config.force_metalink, parse_bool, 0, 0 },
	{ "force-rss", &config.force_rss, parse_bool, 0, 0 },
	{ "force-sitemap", &config.force_sitemap, parse_bool, 0, 0 },
	{ "fsync-policy", &config.fsync_policy, parse_bool, 0, 0 },
	{ "gnutls-options", &config.gnutls_options, parse_string, 1, 0 },
	{ "help", NULL, print_help, 0, 'h' },
	{ "host-directories", &config.host_directories, parse_bool, 0, 0 },
	{ "hsts", &config.hsts, parse_bool, 0, 0 },
	{ "hsts-file", &config.hsts_file, parse_string, 1, 0 },
	{ "html-extension", &config.adjust_extension, parse_bool, 0, 0 }, // obsolete, replaced by --adjust-extension
	{ "http-keep-alive", &config.keep_alive, parse_bool, 0, 0 },
	{ "http-password", &config.http_password, parse_string, 1, 0 },
	{ "http-proxy", &config.http_proxy, parse_string, 1, 0 },
	{ "http-user", &config.http_username, parse_string, 1, 0 },
	{ "http2", &config.http2, parse_bool, 0, 0 },
	{ "https-only", &config.https_only, parse_bool, 0, 0 },
	{ "https-proxy", &config.https_proxy, parse_string, 1, 0 },
	{ "ignore-case", &config.ignore_case, parse_bool, 0, 0 },
	{ "ignore-tags", &config.ignore_tags, parse_taglist, 1, 0 },
	{ "inet4-only", &config.inet4_only, parse_bool, 0, '4' },
	{ "inet6-only", &config.inet6_only, parse_bool, 0, '6' },
	{ "input-encoding", &config.input_encoding, parse_string, 1, 0 },
	{ "input-file", &config.input_file, parse_string, 1, 'i' },
	{ "iri", NULL, parse_bool, 0, 0 }, // Wget compatibility, in fact a do-nothing option
	{ "keep-session-cookies", &config.keep_session_cookies, parse_bool, 0, 0 },
	{ "level", &config.level, parse_integer, 1, 'l' },
	{ "load-cookies", &config.load_cookies, parse_string, 1, 0 },
	{ "local-encoding", &config.local_encoding, parse_string, 1, 0 },
	{ "max-redirect", &config.max_redirect, parse_integer, 1, 0 },
	{ "max-threads", &config.max_threads, parse_integer, 1, 0 },
	{ "metalink", &config.metalink, parse_bool, 0, 0 },
	{ "mirror", &config.mirror, parse_mirror, 0, 'm' },
	{ "n", NULL, parse_n_option, 1, 'n' }, // special Wget compatibility option
	{ "netrc", &config.netrc, parse_bool, 0, 0 },
	{ "netrc-file", &config.netrc_file, parse_string, 1, 0 },
	{ "ocsp", &config.ocsp, parse_bool, 0, 0 },
	{ "ocsp-file", &config.ocsp_file, parse_string, 1, 0 },
	{ "ocsp-stapling", &config.ocsp_stapling, parse_bool, 0, 0 },
	{ "output-document", &config.output_document, parse_string, 1, 'O' },
	{ "output-file", &config.logfile, parse_string, 1, 'o' },
	{ "page-requisites", &config.page_requisites, parse_bool, 0, 'p' },
	{ "parent", &config.parent, parse_bool, 0, 0 },
	{ "password", &config.password, parse_string, 1, 0 },
	{ "post-data", &config.post_data, parse_string, 1, 0 },
	{ "post-file", &config.post_file, parse_string, 1, 0 },
	{ "prefer-family", &config.preferred_family, parse_prefer_family, 1, 0 },
	{ "private-key", &config.private_key, parse_string, 1, 0 },
	{ "private-key-type", &config.private_key_type, parse_cert_type, 1, 0 },
	{ "progress", &config.progress, parse_progress_type, 1, 0 },
	{ "protocol-directories", &config.protocol_directories, parse_bool, 0, 0 },
	{ "quiet", &config.quiet, parse_bool, 0, 'q' },
	{ "quota", &config.quota, parse_numbytes, 1, 'Q' },
	{ "random-file", &config.random_file, parse_string, 1, 0 },
	{ "random-wait", &config.random_wait, parse_bool, 0, 0 },
	{ "read-timeout", &config.read_timeout, parse_timeout, 1, 0 },
	{ "recursive", &config.recursive, parse_bool, 0, 'r' },
	{ "referer", &config.referer, parse_string, 1, 0 },
	{ "reject", &config.reject_patterns, parse_stringlist, 1, 'R' },
	{ "remote-encoding", &config.remote_encoding, parse_string, 1, 0 },
	{ "restrict-file-names", &config.restrict_file_names, parse_restrict_names, 1, 0 },
	{ "robots", &config.robots, parse_bool, 0, 0 },
	{ "save-cookies", &config.save_cookies, parse_string, 1, 0 },
	{ "save-headers", &config.save_headers, parse_bool, 0, 0 },
	{ "secure-protocol", &config.secure_protocol, parse_string, 1, 0 },
	{ "server-response", &config.server_response, parse_bool, 0, 'S' },
	{ "span-hosts", &config.span_hosts, parse_bool, 0, 'H' },
	{ "spider", &config.spider, parse_bool, 0, 0 },
	{ "strict-comments", &config.strict_comments, parse_bool, 0, 0 },
	{ "tcp-fastopen", &config.tcp_fastopen, parse_bool, 0, 0 },
	{ "timeout", NULL, parse_timeout, 1, 'T' },
	{ "timestamping", &config.timestamping, parse_bool, 0, 'N' },
	{ "tls-false-start", &config.tls_false_start, parse_bool, 0, 0 },
	{ "tls-resume", &config.tls_resume, parse_bool, 0, 0 },
	{ "tls-session-file", &config.tls_session_file, parse_string, 1, 0 },
	{ "tries", &config.tries, parse_integer, 1, 't' },
	{ "trust-server-names", &config.trust_server_names, parse_bool, 0, 0 },
	{ "use-server-timestamps", &config.use_server_timestamps, parse_bool, 0, 0 },
	{ "user", &config.username, parse_string, 1, 0 },
	{ "user-agent", &config.user_agent, parse_string, 1, 'U' },
	{ "verbose", &config.verbose, parse_bool, 0, 'v' },
	{ "version", &config.print_version, parse_bool, 0, 'V' },
	{ "wait", &config.wait, parse_timeout, 1, 'w' },
	{ "waitretry", &config.waitretry, parse_timeout, 1, 0 }
};

static int G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL_ALL opt_compare(const void *key, const void *option)
{
	return strcmp((const char *)key, ((const option_t)option)->long_name);
}

static int G_GNUC_WGET_PURE G_GNUC_WGET_NONNULL_ALL opt_compare_execute(const void *key, const void *option)
{
	const char *s1 = (char *)key;
	const char *s2 = ((const option_t)option)->long_name;

	while (*s1 && *s2) {
		if (*s1 == '-' || *s1 == '_') s1++;
		if (*s2 == '-' || *s2 == '_') s2++;
		if (*s1 != *s2) break;
		s1++; s2++;
	}

	return *s1 - *s2;
}

static int G_GNUC_WGET_NONNULL((1)) set_long_option(const char *name, const char *value)
{
	option_t opt;
	int invert = 0, ret = 0;
	char namebuf[strlen(name) + 1], *p;

	if (!strncmp(name, "no-", 3)) {
		invert = 1;
		name += 3;
	}

	if ((p = strchr(name, '='))) {
		// option with appended value
		memcpy(namebuf, name, p - name);
		namebuf[p - name] = 0;
		name = namebuf;
		value = p + 1;
	}

	opt = bsearch(name, options, countof(options), sizeof(options[0]), opt_compare);
	if (!opt) {
		// Maybe the user asked for e.g. https_only or httpsonly instead of https-only
		// opt_compare_execute() will find these. Wget -e/--execute compatibility.
		opt = bsearch(name, options, countof(options), sizeof(options[0]), opt_compare_execute);
	}

	if (!opt)
		error_printf_exit(_("Unknown option '%s'\n"), name);

	if (name != namebuf && opt->parser == parse_bool)
		value = NULL;

	debug_printf("name=%s value=%s invert=%d\n", opt->long_name, value, invert);

	if (opt->parser == parse_string && invert) {
		// allow no-<string-option> to set value to NULL
		if (value && name == namebuf)
			error_printf_exit(_("Option 'no-%s' doesn't allow an argument\n"), name);

		parse_string(opt, NULL);
	}
	else if (opt->parser == parse_stringset && invert) {
		// allow no-<string-option> to set value to NULL
		if (value && name == namebuf)
			error_printf_exit(_("Option 'no-%s' doesn't allow an argument\n"), name);

		parse_stringset(opt, NULL);
	}
	else {
		if (value && !opt->args && opt->parser != parse_bool)
			error_printf_exit(_("Option '%s' doesn't allow an argument\n"), name);

		if (opt->args) {
			if (!value)
				error_printf_exit(_("Missing argument for option '%s'\n"), name);

			opt->parser(opt, value);

			if (name != namebuf)
				ret = opt->args;
		}
		else {
			if (opt->parser == parse_bool) {
				opt->parser(opt, value);

				if (invert && opt->var)
					*((char *)opt->var) = !*((char *)opt->var); // invert boolean value
			} else
				opt->parser(opt, NULL);
		}
	}

	return ret;
}

static int parse_execute(G_GNUC_WGET_UNUSED option_t opt, const char *val)
{
	// info_printf("### argv=%s val=%s\n",argv[0],val);
	set_long_option(val, NULL);

	return 0;
}

static int _parse_option(char *linep, char **name, char **val)
{
	int quote;

	while (isspace(*linep)) linep++;
	for (*name = linep; isalnum(*linep) || *linep == '-'; linep++);

	if (!**name) {
		error_printf(_("Failed to parse: '%s'\n"), linep);
		// continue;
		return 0;
	}

	if (*linep == '=') {
		// option with value, e.g. debug=y
		*linep++ = 0;
		// while (c_isspace(linep)) linep++;

		*val = linep;

		if (((quote = *linep) == '\"' || quote == '\'')) {
			char *src = linep + 1, *dst = linep, c;

			while ((c = *src) != quote && c) {
				if (c == '\\') {
					// we could extend \r, \n etc to control codes here
					// but it is not needed so far
					*dst++ = src[1];
					src += 2;
				} else *dst++ = *src++;
			}
			*dst = 0;
		}
		return 1;
	} else {
		// statement (e.g. include ".wgetrc.d") or boolean option without value (e.g. no-recursive)
		if (*linep) *linep++ = 0;
		while (isspace(*linep)) linep++;
		*val = linep;
		return 2;
	}
}

// read and parse config file (not thread-safe !)
// - first, leading and trailing whitespace are trimmed
// - lines beginning with '#' are comments, except the line before has a trailing slash
// - there are no multiline comments (trailing \ on comments will be ignored)
// - empty lines are ignored
// - lines consisting only of whitespace are ignored
// - a trailing \ will append the next line (this does not go for comments!)
// - if the last line has a trailing \, it will be ignored
// - format is 'name value', where value might be enclosed in ' or "
// - values enclosed in " or ' might contain \\, \" and \'

static int G_GNUC_WGET_NONNULL((1)) _read_config(const char *cfgfile, int expand)
{
	static int level; // level of recursions to prevent endless include loops
	FILE *fp;
	char *buf = NULL, *linep, *name, *val;
	int append = 0, found;
	size_t bufsize = 0;
	ssize_t len;
	wget_buffer_t linebuf;

	if (expand) {
		glob_t globbuf = { .gl_pathc = 0 };

		if (glob(cfgfile, GLOB_MARK | GLOB_TILDE, NULL, &globbuf) == 0) {
			size_t it;

			for (it = 0; it < globbuf.gl_pathc; it++) {
				if (globbuf.gl_pathv[it][strlen(globbuf.gl_pathv[it])-1] != '/') {
					_read_config(globbuf.gl_pathv[it], 0);

					level--;
				}
			}
			globfree(&globbuf);

		} else {
			if (++level > 20)
				error_printf_exit(_("Config file recursion detected in %s\n"), cfgfile);

			_read_config(cfgfile, 0);
			
			level--;
		}
		
		return 0;
	}

	if ((fp = fopen(cfgfile, "r")) == NULL) {
		error_printf(_("Failed to open %s\n"), cfgfile);
		return -1;
	}

	debug_printf("Reading %s\n", cfgfile);

	char tmp[1024];
	wget_buffer_init(&linebuf, tmp, sizeof(tmp));

	while ((len = wget_getline(&buf, &bufsize, fp)) >= 0) {
		if (len == 0 || *buf == '\r' || *buf == '\n') continue;

		linep = buf;

		// remove leading whitespace (only on non-continuation lines)
		if (!append)
			while (isspace(*linep)) {
				linep++;
				len--;
			}
		if (*linep == '#') continue;

		// remove trailing whitespace
		while (len > 0 && isspace(linep[len - 1]))
			len--;
		linep[len] = 0;

		if (linep[len - 1] == '\\') {
			if (append) {
				wget_buffer_memcat(&linebuf, linep, len - 1);
			} else {
				wget_buffer_memcpy(&linebuf, linep, len - 1);
				append = 1;
			}
			continue;
		} else if (append) {
			wget_buffer_strcat(&linebuf, linep);
			append = 0;
			linep = linebuf.data;
		}

		found = _parse_option(linep, &name, &val);

		if (found == 1) {
			// debug_printf("%s = %s\n",name,val);
			set_long_option(name, val);
		} else if (found == 2) {
			// debug_printf("%s %s\n",name,val);
			if (!strcmp(name, "include")) {
				if (++level > 20)
					error_printf_exit(_("Config file recursion loop detected in %s\n"), cfgfile);

				_read_config(val, 1);

				level--;
			} else {
				set_long_option(name, NULL);
			}
		}
	}

	wget_buffer_deinit(&linebuf);
	xfree(buf);
	fclose(fp);

	if (append) {
		error_printf(_("Failed to parse last line in '%s'\n"), cfgfile);
	}

	return 0;
}

static void read_config(void)
{
	if (access(SYSCONFDIR"wgetrc", R_OK) == 0)
		_read_config(SYSCONFDIR"wgetrc", 0);

	if (config.config_file)
		_read_config(config.config_file, 1);
}

static int G_GNUC_WGET_NONNULL((2)) parse_command_line(int argc, const char **argv)
{
	static short shortcut_to_option[128];
	const char *first_arg = NULL;
	int n;

	// init the short option lookup table
	if (!shortcut_to_option[0]) {
		for (unsigned it = 0; it < countof(options); it++) {
			if (options[it].short_name > 0)
				shortcut_to_option[(unsigned char)options[it].short_name] = it + 1;
		}
	}

	// I like the idea of getopt() but not it's implementation (e.g. global variables).
	// Therefore I implement my own getopt() behaviour.
	for (n = 1; n < argc && first_arg != argv[n]; n++) {
		const char *argp = argv[n];

		if (argp[0] != '-') {
			// Move args behind options to allow mixed args/options like getopt().
			// In the end, the order of the args is as before.
			const char *cur = argv[n];
			for (int it = n; it < argc - 1; it++)
				argv[it] = argv[it + 1];
			argv[argc - 1] = cur;

			// Once we see the first arg again, we are done
			if (!first_arg)
				first_arg = cur;

			n--;
			continue;
		}

		if (argp[1] == '-') {
			// long option
			if (argp[2] == 0)
				return n + 1;

			n += set_long_option(argp + 2, n < argc - 1 ? argv[n+1] : NULL);

		} else if (argp[1]) {
			// short option(s)
			for (int pos = 1; argp[pos]; pos++) {
				option_t opt;
				int idx;

				if (isalnum(argp[pos]) && (idx = shortcut_to_option[(unsigned char)argp[pos]])) {
					opt = &options[idx - 1];
					// info_printf("opt=%p [%c]\n",(void *)opt,argp[pos]);
					// info_printf("name=%s\n",opt->long_name);
					if (opt->args) {
						const char *val;

						if (!argp[pos + 1] && argc <= n + opt->args)
							error_printf_exit(_("Missing argument(s) for option '-%c'\n"), argp[pos]);
						val = argp[pos + 1] ? argp + pos + 1 : argv[++n];
						n += opt->parser(opt, val);
						break;
					} else
						opt->parser(opt, NULL);
				} else
					error_printf_exit(_("Unknown option '-%c'\n"), argp[pos]);
			}
		}
	}

	return n;
}

static void G_GNUC_WGET_NORETURN _no_memory(void)
{
	fprintf(stderr, "No memory\n");
	exit(EXIT_FAILURE);
}


// Return the user's home directory (strdup-ed), or NULL if none is found.
// TODO: Read the XDG Base Directory variables first
static char *get_home_dir(void)
{
	static char *home;

	if (!home) {
		glob_t globbuf = { .gl_pathc = 0 };

		// Gnulib covers all the gory details for non-Linux systems
		if (glob("~", GLOB_TILDE_CHECK, NULL, &globbuf) == 0) {
			if (globbuf.gl_pathc > 0)
				home = wget_strdup(globbuf.gl_pathv[0]);

			globfree(&globbuf);
		} else {
			home = wget_strdup("."); // Use the current directory as 'home' directory
		}
	}

	return home;
}

// read config, parse CLI options, check values, set module options
// and return the number of arguments consumed

int init(int argc, const char **argv)
{
	int n;

	// set libwget out-of-memory function
	wget_set_oomfunc(_no_memory);

	// this is a special case for switching on debugging before any config file is read
	if (argc >= 2) {
		if (!strcmp(argv[1],"-d"))
			config.debug = 1;
		else if (!strcmp(argv[1],"--debug")) {
			set_long_option(argv[1] + 2, argv[2]);
		}
	}

	// the following strdup's are just needed for reallocation/freeing purposes to
	// satisfy valgrind
	config.user_agent = strdup(config.user_agent);
	config.secure_protocol = strdup(config.secure_protocol);
	config.ca_directory = strdup(config.ca_directory);
	config.http_proxy = wget_strdup(getenv("http_proxy"));
	config.https_proxy = wget_strdup(getenv("https_proxy"));
	config.default_page = strdup(config.default_page);
	config.domains = wget_vector_create(16, -2, (int (*)(const void *, const void *))strcmp);
//	config.exclude_domains = wget_vector_create(16, -2, NULL);

	log_init();

	// first processing, to respect options that might influence output
	// while read_config() (e.g. -d, -q, -a, -o)
	parse_command_line(argc, argv);

	// truncate logfile, if not in append mode
	if (config.logfile_append) {
		config.logfile = config.logfile_append;
		config.logfile_append = NULL;
	}
	else if (config.logfile && strcmp(config.logfile,"-")) {
		int fd = open(config.logfile, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}
	log_init();

	// Initialize some configuration values which depend on the Runtime environment
	char *home_dir = get_home_dir();

	if (!config.hsts_file)
		config.hsts_file = wget_str_asprintf("%s/.wget-hsts", home_dir);

	if (config.tls_resume && !config.tls_session_file)
		config.tls_session_file = wget_str_asprintf("%s/.wget-session", home_dir);

	if (!config.ocsp_file)
		config.ocsp_file = wget_str_asprintf("%s/.wget-ocsp", home_dir);

	if (config.netrc && !config.netrc_file)
		config.netrc_file = wget_str_asprintf("%s/.netrc", home_dir);

	if (!config.config_file) {
		config.config_file = wget_str_asprintf("%s/.wgetrc", home_dir);
		if (access(config.config_file, R_OK))
			xfree(config.config_file); // we don't want to complain about missing home .wgetrc
	} else if (access(config.config_file, R_OK)) {
		error_printf(_("Failed to open config file '%s'\n"), config.config_file);
		xfree(config.config_file);
	}

	xfree(home_dir);

	// read global config and user's config
	// settings in user's config override global settings
	read_config();

	if (config.print_version) {
		info_printf("Wget " PACKAGE_VERSION " - C multithreaded metalink/file/website downloader\n\n");
		info_printf("+digest"

#if defined WITH_GNUTLS
	" +https"
#else
	" -https"
#endif

	" +ipv6"
	" +iri"

#if SIZEOF_OFF_T >= 8
	" +large-file"
#else
	" -large-file"
#endif

#if defined ENABLE_NLS
	" +nls"
#else
	" -nls"
#endif

#if defined ENABLE_NTLM
  " +ntlm"
#else
  " -ntlm"
#endif

#if defined ENABLE_OPIE
	" +opie"
#else
	" -opie"
#endif

#if defined WITH_LIBPSL
	" +psl"
#else
	" -psl"
#endif

#if defined WITH_GNUTLS
	" +ssl/gnutls"
#else
	" -ssl"
#endif

#if defined HAVE_ICONV
	" +iconv"
#else
	" -iconv"
#endif

#if defined WITH_LIBIDN2
	" +idn2"
#elif defined WITH_LIBIDN
	" +idn"
#else
	" -idn"
#endif

#if defined WITH_LIBUNISTRING
	" +unistring"
#else
	" -unistring"
#endif

#if defined WITH_ZLIB
	" +zlib"
#else
	" -zlib"
#endif

#if defined WITH_LZMA
	" +lzma"
#else
	" -lzma"
#endif

#if defined WITH_BZIP2
	" +bzip2"
#else
	" -bzip2"
#endif

#if defined WITH_LIBNGHTTP2
	" +http2"
#else
	" -http2"
#endif

			"\n");
	}

	// now read command line options which override the settings of the config files
	n = parse_command_line(argc, argv);

	if (config.logfile_append) {
		config.logfile = config.logfile_append;
		config.logfile_append = NULL;
	}
	else if (config.logfile && strcmp(config.logfile,"-")) {
		// truncate logfile
		int fd = open(config.logfile, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}
	log_init();

	// check for correct settings
	if (config.max_threads < 1)
		config.max_threads = 1;

	// truncate output document
	if (config.output_document && strcmp(config.output_document,"-")) {
		int fd = open(config.output_document, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}

	if (!config.local_encoding)
		config.local_encoding = wget_local_charset_encoding();
	if (!config.input_encoding)
		config.input_encoding = strdup(config.local_encoding);

	debug_printf("Local URI encoding = '%s'\n", config.local_encoding);
	debug_printf("Input URI encoding = '%s'\n", config.input_encoding);

	if (config.http_proxy && wget_http_set_http_proxy(config.http_proxy, config.local_encoding) < 0) {
		error_printf(_("Failed to set http proxies %s\n"), config.http_proxy);
		return -1;
	}
	if (config.https_proxy && wget_http_set_https_proxy(config.https_proxy, config.local_encoding) < 0) {
		error_printf(_("Failed to set https proxies %s\n"), config.https_proxy);
		return -1;
	}
	xfree(config.http_proxy);
	xfree(config.https_proxy);

	if (config.cookies) {
		config.cookie_db = wget_cookie_db_init(NULL);
		wget_cookie_set_keep_session_cookies(config.cookie_db, config.keep_session_cookies);
		if (config.cookie_suffixes)
			wget_cookie_db_load_psl(config.cookie_db, config.cookie_suffixes);
		if (config.load_cookies)
			wget_cookie_db_load(config.cookie_db, config.load_cookies);
	}

	if (config.hsts) {
		config.hsts_db = wget_hsts_db_init(NULL);
		wget_hsts_db_load(config.hsts_db, config.hsts_file);
	}

	if (config.tls_resume) {
		config.tls_session_db = wget_tls_session_db_init(NULL);
		wget_tls_session_db_load(config.tls_session_db, config.tls_session_file);
	}

	if (config.ocsp) {
		config.ocsp_db = wget_ocsp_db_init(NULL);
		wget_ocsp_db_load(config.ocsp_db, config.ocsp_file);
	}

	if (config.base_url)
		config.base = wget_iri_parse(config.base_url, config.local_encoding);

	if (config.username && !config.http_username)
		config.http_username = strdup(config.username);

	if (config.password && !config.http_password)
		config.http_password = strdup(config.password);

	if (config.page_requisites && !config.recursive) {
		config.recursive = 1;
		config.level = 1;
	}

	if (config.mirror)
		config.metalink = 0;

	// set module specific options
	wget_tcp_set_timeout(NULL, config.read_timeout);
	wget_tcp_set_connect_timeout(NULL, config.connect_timeout);
	wget_tcp_set_dns_timeout(NULL, config.dns_timeout);
	wget_tcp_set_dns_caching(NULL, config.dns_caching);
	wget_tcp_set_tcp_fastopen(NULL, config.tcp_fastopen);
	wget_tcp_set_tls_false_start(NULL, config.tls_false_start);
	wget_tcp_set_bind_address(NULL, config.bind_address);
	if (config.inet4_only)
		wget_tcp_set_family(NULL, WGET_NET_FAMILY_IPV4);
	else if (config.inet6_only)
		wget_tcp_set_family(NULL, WGET_NET_FAMILY_IPV6);
	else
		wget_tcp_set_preferred_family(NULL, config.preferred_family);

	wget_iri_set_defaultpage(config.default_page);

	// SSL settings
	wget_ssl_set_config_int(WGET_SSL_CHECK_CERTIFICATE, config.check_certificate);
	wget_ssl_set_config_int(WGET_SSL_CHECK_HOSTNAME, config.check_hostname);
	wget_ssl_set_config_int(WGET_SSL_CERT_TYPE, config.cert_type);
	wget_ssl_set_config_int(WGET_SSL_KEY_TYPE, config.private_key_type);
	wget_ssl_set_config_int(WGET_SSL_PRINT_INFO, config.debug);
	wget_ssl_set_config_int(WGET_SSL_OCSP, config.ocsp);
	wget_ssl_set_config_int(WGET_SSL_OCSP_STAPLING, config.ocsp_stapling);
	wget_ssl_set_config_string(WGET_SSL_SECURE_PROTOCOL, config.secure_protocol);
	wget_ssl_set_config_string(WGET_SSL_DIRECT_OPTIONS, config.gnutls_options);
	wget_ssl_set_config_string(WGET_SSL_CA_DIRECTORY, config.ca_directory);
	wget_ssl_set_config_string(WGET_SSL_CA_FILE, config.ca_cert);
	wget_ssl_set_config_string(WGET_SSL_CERT_FILE, config.cert_file);
	wget_ssl_set_config_string(WGET_SSL_KEY_FILE, config.private_key);
	wget_ssl_set_config_string(WGET_SSL_CRL_FILE, config.crl_file);
	wget_ssl_set_config_string(WGET_SSL_OCSP_CACHE, (const char *)config.ocsp_db);
	wget_ssl_set_config_string(WGET_SSL_ALPN, config.http2 ? "h2,h2-16,h2-14,http/1.1" : NULL);
	wget_ssl_set_config_string(WGET_SSL_SESSION_CACHE, (const char *)config.tls_session_db);

	// convert host lists to lowercase
	for (int it = 0; it < wget_vector_size(config.domains); it++) {
		char *s, *hostname = wget_vector_get(config.domains, it);

		wget_percent_unescape(hostname);

		if (wget_str_needs_encoding(hostname)) {
			if ((s = wget_str_to_utf8(hostname, config.local_encoding))) {
				wget_vector_replace_noalloc(config.domains, s, it);
				hostname = s;
			}

			if ((s = (char *)wget_str_to_ascii(hostname)) != hostname)
				wget_vector_replace_noalloc(config.domains, s, it);
		} else
			wget_strtolower(hostname);
	}

	for (int it = 0; it < wget_vector_size(config.exclude_domains); it++) {
		char *s, *hostname = wget_vector_get(config.exclude_domains, it);

		wget_percent_unescape(hostname);

		if (wget_str_needs_encoding(hostname)) {
			if ((s = wget_str_to_utf8(hostname, config.local_encoding))) {
				wget_vector_replace_noalloc(config.exclude_domains, s, it);
				hostname = s;
			}

			if ((s = (char *)wget_str_to_ascii(hostname)) != hostname)
				wget_vector_replace_noalloc(config.exclude_domains, s, it);
		} else
			wget_strtolower(hostname);
	}

	return n;
}

// just needs to be called to free all allocated storage on exit
// for valgrind testing

void deinit(void)
{
	wget_dns_cache_free(); // frees DNS cache
	wget_tcp_set_bind_address(NULL, NULL); // free global bind address

	wget_cookie_db_free(&config.cookie_db);
	wget_hsts_db_free(&config.hsts_db);
	wget_tls_session_db_free(&config.tls_session_db);
	wget_ocsp_db_free(&config.ocsp_db);
	wget_netrc_db_free(&config.netrc_db);
	wget_ssl_deinit();

	xfree(config.cookie_suffixes);
	xfree(config.load_cookies);
	xfree(config.save_cookies);
	xfree(config.hsts_file);
	xfree(config.tls_session_file);
	xfree(config.ocsp_file);
	xfree(config.netrc_file);
	xfree(config.config_file);
	xfree(config.logfile);
	xfree(config.logfile_append);
	xfree(config.user_agent);
	xfree(config.output_document);
	xfree(config.ca_cert);
	xfree(config.ca_directory);
	xfree(config.cert_file);
	xfree(config.crl_file);
	xfree(config.egd_file);
	xfree(config.private_key);
	xfree(config.random_file);
	xfree(config.secure_protocol);
	xfree(config.default_page);
	xfree(config.base_url);
	xfree(config.input_file);
	xfree(config.input_encoding);
	xfree(config.local_encoding);
	xfree(config.remote_encoding);
	xfree(config.username);
	xfree(config.password);
	xfree(config.http_username);
	xfree(config.http_password);
	xfree(config.post_data);
	xfree(config.post_file);

	wget_iri_free(&config.base);

	wget_vector_free(&config.domains);
	wget_vector_free(&config.exclude_domains);
	wget_vector_free(&config.follow_tags);
	wget_vector_free(&config.ignore_tags);
	wget_vector_free(&config.accept_patterns);
	wget_vector_free(&config.reject_patterns);

	wget_http_set_http_proxy(NULL, NULL);
	wget_http_set_https_proxy(NULL, NULL);
}

// self test some functions, called by using --self-test

int selftest_options(void)
{
	int ret = 0;
	size_t it;

	// check if all options are available

	for (it = 0; it < countof(options); it++) {
		option_t opt = bsearch(options[it].long_name, options, countof(options), sizeof(options[0]), opt_compare);
		if (!opt) {
			error_printf("%s: Failed to find option '%s'\n", __func__, options[it].long_name);
			ret = 1;
		}
	}

	// test parsing boolean short and long option

	{
		static struct {
			const char
				*argv[3];
			char
				result;
		} test_bool_short[] = {
			{ { "", "-r", "-" }, 1 },
		};

		// save config values
		char recursive = config.recursive;

		for (it = 0; it < countof(test_bool_short); it++) {
			config.recursive = 2; // invalid bool value
			parse_command_line(3, test_bool_short[it].argv);
			if (config.recursive != test_bool_short[it].result) {
				error_printf("%s: Failed to parse bool short option #%zu (=%d)\n", __func__, it, config.recursive);
				ret = 1;
			}
		}

		static struct {
			const char
				*argv[3];
			char
				result;
		} test_bool[] = {
			{ { "", "--recursive", "" }, 1 },
			{ { "", "--no-recursive", "" }, 0 },
			{ { "", "--recursive=y", "" }, 1 },
			{ { "", "--recursive=n", "" }, 0 },
			{ { "", "--recursive=1", "" }, 1 },
			{ { "", "--recursive=0", "" }, 0 },
			{ { "", "--recursive=yes", "" }, 1 },
			{ { "", "--recursive=no", "" }, 0 },
			{ { "", "--recursive=on", "" }, 1 },
			{ { "", "--recursive=off", "" }, 0 }
		};

		for (it = 0; it < countof(test_bool); it++) {
			config.recursive = 2; // invalid bool value
			parse_command_line(2, test_bool[it].argv);
			if (config.recursive != test_bool[it].result) {
				error_printf("%s: Failed to parse bool long option #%zu (%d)\n", __func__, it, config.recursive);
				ret = 1;
			}

			config.recursive = 2; // invalid bool value
			parse_command_line(3, test_bool[it].argv);
			if (config.recursive != test_bool[it].result) {
				error_printf("%s: Failed to parse bool long option #%zu (%d)\n", __func__, it, config.recursive);
				ret = 1;
			}
		}

		// restore config values
		config.recursive = recursive;
	}

	// test parsing timeout short and long option

	{
		static struct {
			const char
				*argv[3];
			int
				result;
		} test_timeout_short[] = {
			{ { "", "-T", "123" }, 123000 },
			{ { "", "-T", "-1" }, -1 },
			{ { "", "-T", "inf" }, -1 },
			{ { "", "-T", "infinity" }, -1 },
			{ { "", "-T", "0" }, -1 }, // -1 due to special wget compatibility
			{ { "", "-T", "+123" }, 123000 },
			{ { "", "-T", "60.2" }, 60200 },
			{ { "", "-T123", "" }, 123000 },
			{ { "", "-T-1", "" }, -1 },
			{ { "", "-Tinf", "" }, -1 },
			{ { "", "-Tinfinity", "" }, -1 },
			{ { "", "-T0", "" }, -1 }, // -1 due to special wget compatibility
			{ { "", "-T+123", "" }, 123000 },
			{ { "", "-T60.2", "" }, 60200 }
		};

		// save config values
		int dns_timeout = config.dns_timeout;
		int connect_timeout = config.connect_timeout;
		int read_timeout = config.read_timeout;

		for (it = 0; it < countof(test_timeout_short); it++) {
			config.dns_timeout = 555; // some value not used in test
			parse_command_line(3, test_timeout_short[it].argv);
			if (config.dns_timeout != test_timeout_short[it].result) {
				error_printf("%s: Failed to parse timeout short option #%zu (=%d)\n", __func__, it, config.dns_timeout);
				ret = 1;
			}
		}

		static struct {
			const char
				*argv[3];
			int
				result;
		} test_timeout[] = {
			{ { "", "--timeout", "123" }, 123000 },
			{ { "", "--timeout", "-1" }, -1 },
			{ { "", "--timeout", "inf" }, -1 },
			{ { "", "--timeout", "infinity" }, -1 },
			{ { "", "--timeout", "0" }, -1 }, // -1 due to special wget compatibility
			{ { "", "--timeout", "+123" }, 123000 },
			{ { "", "--timeout", "60.2" }, 60200 },
			{ { "", "--timeout=123", "" }, 123000 },
			{ { "", "--timeout=-1", "" }, -1 },
			{ { "", "--timeout=inf", "" }, -1 },
			{ { "", "--timeout=infinity", "" }, -1 },
			{ { "", "--timeout=0", "" }, -1 }, // -1 due to special wget compatibility
			{ { "", "--timeout=+123", "" }, 123000 },
			{ { "", "--timeout=60.2", "" }, 60200 }
		};

		for (it = 0; it < countof(test_timeout); it++) {
			config.dns_timeout = 555;  // some value not used in test
			parse_command_line(3, test_timeout[it].argv);
			if (config.dns_timeout != test_timeout[it].result) {
				error_printf("%s: Failed to parse timeout long option #%zu (%d)\n", __func__, it, config.dns_timeout);
				ret = 1;
			}
		}

		// restore config values
		config.dns_timeout = dns_timeout;
		config.connect_timeout = connect_timeout;
		config.read_timeout = read_timeout;
	}

	// test parsing string short and long option

	{
		static struct {
			const char
				*argv[3];
			const char
				*result;
		} test_string_short[] = {
			{ { "", "-U", "hello1" }, "hello1" },
			{ { "", "-Uhello2", "" }, "hello2" }
		};

		// save config values
		const char *user_agent = config.user_agent;
		config.user_agent = NULL;

		for (it = 0; it < countof(test_string_short); it++) {
			parse_command_line(3, test_string_short[it].argv);
			if (wget_strcmp(config.user_agent, test_string_short[it].result)) {
				error_printf("%s: Failed to parse string short option #%zu (=%s)\n", __func__, it, config.user_agent);
				ret = 1;
			}
		}

		static struct {
			const char
				*argv[3];
			const char
				*result;
		} test_string[] = {
			{ { "", "--user-agent", "hello3" }, "hello3" },
			{ { "", "--user-agent=hello4", "" }, "hello4" },
			{ { "", "--no-user-agent", "" }, NULL }
		};

		for (it = 0; it < countof(test_string); it++) {
			parse_command_line(3, test_string[it].argv);
			if (wget_strcmp(config.user_agent, test_string[it].result)) {
				error_printf("%s: Failed to parse string short option #%zu (=%s)\n", __func__, it, config.user_agent);
				ret = 1;
			}
		}

		// restore config values
		xfree(config.user_agent);
		config.user_agent = user_agent;
	}

	return ret;
}
