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

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <glob.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "xalloc.h"
#include "utils.h"
#include "log.h"
#include "net.h"
#include "ssl.h"
#include "buffer.h"
#include "cookie.h"
#include "options.h"
#include "iri.h"
#include "http.h"

typedef const struct option *option_t; // forward declaration

struct option {
	const char
		*long_name;
	void
		*var;
	int
		(*parser)(option_t opt, const char *const *argv, const char *val);
	int
		args;
	char
		short_name;
};

static int print_version(UNUSED option_t opt, UNUSED const char *const *argv, UNUSED const char *val)
{
	info_printf("mget V"MGET_VERSION" - C multithreaded metalink/file/website downloader\n");

	return 0;
}

static int NORETURN print_help(UNUSED option_t opt, UNUSED const char *const *argv, UNUSED const char *val)
{
	puts(
		"Mget V"MGET_VERSION" - multithreaded metalink/file/website downloader written in C\n"
		"\n"
		"Usage: mget [options...] <url>...\n"
		"\n"
		"Startup:\n"
		"  -V  --version           Display the version of Wget and exit.\n"
		"  -h  --help              Print this help.\n"
		"  -v  --verbose           Print more messages. (default: on)\n"
		"  -q  --quiet             Print no messages except debugging messages. (default: off)\n"
		"  -d  --debug             Print debugging messages. (default: off)\n"
		"  -o  --output-file       File where messages are printed to, '-' for STDOUT.\n"
		"  -a  --append-output     File where messages are appended to, '-' for STDOUT.\n"
		"\n");
	puts(
		"Download:\n"
		"  -r  --recursive         Recursive download. (default: off)\n"
		"  -H  --span-hosts        Span hosts that where not given on the command line. (default: off)\n"
		"      --num-threads       Max. concurrent download threads. (default: 5)\n"
		"      --max-redirect      Max. number of redirections to follow. (default: 20)\n"
		"  -T  --timeout           General network timeout in seconds.\n"
		"      --dns-timeout       DNS lookup timeout in seconds.\n"
		"      --connect-timeout   Connect timeout in seconds.\n"
		"      --read-timeout      Read and write timeout in seconds.\n"
		"      --dns-caching       Enable DNS cache. (default: on)\n"
		"  -O  --output-document   File where downloaded content is written to, '-'  for STDOUT.\n"
		"      --spider            Enable web spider mode. (default: off)\n"
		"      --proxy             Enable support for *_proxy environment variables. (default: on)\n"
		"      --http-proxy        Set HTTP proxy, overriding environment variables.\n"
		"      --https-proxy       Set HTTPS proxy, overriding environment variables.\n"
		"  -S  --server-response   Print the server response headers. (default: off)\n"
		"  -c  --continue-download Continue download for given files. (default: off)\n"
		"      --use-server-timestamps Set local file's timestamp to server's timestamp. (default: on)\n"
		"  -N  --timestamping      Just retrieve younger files than the local ones. (default: off)\n"
		"      --strict-comments   A dummy option. Parsing always works non-strict."
		"      --delete-after      Don't save downloaded files. (default: off)\n"
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
		"                          mget -O suffixes.txt http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1\n"
		"      --http-keep-alive   Keep connection open for further requests. (default: on)\n"
		"\n");
	puts(
		"HTTPS (SSL/TLS) related options:\n"
		"      --secure-protocol   Set protocol to be used (auto, SSLv2, SSLv3 or TLSv1). (default: auto)\n"
		"      --check-certificate Check the server's certificate. (default: on)\n"
		"      --certificate       File with client certificate.\n"
		"      --private-key       File with private key.\n"
		"      --private-key-type  Type of the private key (PEM or DER). (default: PEM)\n"
		"      --ca-certificate    File with bundle of PEM CA certificates.\n"
		"      --ca-directory      Directory with PEM CA certificates.\n"
		"      --random-file       File to be used as source of random data.\n"
		"      --egd-file          File to be used as socket for random data from Entropy Gathering Daemon.\n"
		"\n");
	puts(
		"Directory options:\n"
		"      --directories       Create hierarchy of directories when retrieving recursively. (default: on)\n"
		"  -x  --force-directories Create hierarchy of directories when not retrieving recursively. (default: off)\n"
		"      --host-directories  Force creating host directories. (default: off)\n"
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
 * Using rm logfile + mget achieves the old behaviour...
 *
 */
	exit(0);
}

static int parse_integer(option_t opt, UNUSED const char *const *argv, const char *val)
{
	*((int *)opt->var) = val ? atoi(val) : 0;

	return 0;
}

static int parse_string(option_t opt, UNUSED const char *const *argv, const char *val)
{
	// the strdup'ed string will be released on program exit
	xfree(*((const char **)opt->var));
	*((const char **)opt->var) = val ? strdup(val) : NULL;

	return 0;
}

static int parse_bool(option_t opt, UNUSED const char *const *argv, const char *val)
{
	if (!val)
		*((char *)opt->var) = 1;
	else if (!strcmp(val,"1") || !strcasecmp(val,"y") || !strcasecmp(val,"yes") || !strcasecmp(val,"on"))
		*((char *)opt->var) = 1;
	else if (!strcmp(val,"0") || !strcasecmp(val,"n") || !strcasecmp(val,"no") || !strcasecmp(val,"off"))
		*((char *)opt->var) = 0;
	else {
		err_printf(_("Boolean value '%s' not recognized\n"), val);
	}

	return 0;
}

static int parse_timeout(option_t opt, UNUSED const char *const *argv, const char *val)
{
	double fval;

	if (!strcasecmp(val, "INF") || !strcasecmp(val, "INFINITY"))
		fval = -1;
	else {
		fval = atof(val)*1000;

		if (fval == 0) // special wget compatibility: timeout 0 means INFINITY
			fval = -1;
	}

	if (fval < 0)
		fval = -1;

	if (opt->var) {
		*((int *)opt->var) = fval;
		// log_printf("timeout set to %gs\n",*((int *)opt->var)/1000.);
	} else {
		// --timeout option sets all timeouts
		config.connect_timeout =
			config.dns_timeout =
			config.read_timeout = fval;
	}

	return 0;
}

static int PURE NONNULL(1) parse_cert_type(option_t opt, UNUSED const char *const *argv, const char *val)
{
	if (!val || !strcasecmp(val, "PEM"))
		*((char *)opt->var) = SSL_X509_FMT_PEM;
	else if (!strcasecmp(val, "DER") || !strcasecmp(val, "ASN1"))
		*((char *)opt->var) = SSL_X509_FMT_DER;
	else
		err_printf_exit("Unknown cert type '%s'\n", val);

	return 0;
}

static int parse_n_option(UNUSED option_t opt, UNUSED const char *const *argv, const char *val)
{
	if (val) {
		const char *p;

		for (p = val; *p; p++) {
			switch (*p) {
			case 'v':
				config.verbose = 0;
				break;
			case 'c':
//				config.clobber = 0;
				break;
			case 'd':
				config.directories = 0;
				break;
			case 'H':
				config.host_directories = 0;
				break;
			case 'p':
//				config.parent = 0;
				break;
			default:
				err_printf_exit(_("Unknown option '-n%c'\n"), *p);
			}

			log_printf("name=-n%c value=0\n", *p);
		}
	}

	return 0;
}

// default values for config options (if not 0 or NULL)
struct config config = {
	.connect_timeout = -1,
	.dns_timeout = -1,
	.read_timeout = -1,
	.max_redirect = 20,
	.num_threads = 5,
	.dns_caching = 1,
	.user_agent = "Mget/"MGET_VERSION,
	.verbose = 1,
	.check_certificate=1,
	.cert_type = SSL_X509_FMT_PEM,
	.private_key_type = SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system",
	.cookies = 1,
	.keep_alive=1,
	.use_server_timestamps = 1,
	.directories = 1,
	.host_directories = 1
};

static const struct option options[] = {
	// long name, config variable, parse function, number of arguments, short name
	// leave the entries in alphabetical order of 'long_name' !
	{ "append-output", &config.logfile_append, parse_string, 1, 'a'},
	{ "ca-certificate", &config.ca_cert, parse_string, 1, 0},
	{ "ca-directory", &config.ca_directory, parse_string, 1, 0},
	{ "certificate", &config.cert_file, parse_string, 1, 0},
	{ "certificate-type", &config.cert_type, parse_cert_type, 1, 0},
	{ "check-certificate", &config.check_certificate, parse_bool, 0, 0},
	{ "connect-timeout", &config.connect_timeout, parse_timeout, 1, 0},
	{ "continue-download", &config.continue_download, parse_bool, 0, 'c'},
	{ "cookie-suffixes", &config.cookie_suffixes, parse_string, 1, 0},
	{ "cookies", &config.cookies, parse_bool, 0, 0},
	{ "cut-dirs", &config.cut_directories, parse_integer, 1, 0},
	{ "debug", &config.debug, parse_bool, 0, 'd'},
	{ "delete-after", &config.delete_after, parse_bool, 0, 0},
	{ "directories", &config.directories, parse_bool, 0, 0},
	{ "directory-prefix", &config.directory_prefix, parse_string, 1, 'P'},
	{ "dns-cache", &config.dns_caching, parse_bool, 0, 0},
	{ "dns-timeout", &config.dns_timeout, parse_timeout, 1, 0},
	{ "egd-file", &config.egd_file, parse_string, 1, 0},
	{ "force-directories", &config.force_directories, parse_bool, 0, 'x'},
	{ "help", NULL, print_help, 0, 'h'},
	{ "host-directories", &config.host_directories, parse_bool, 0, 0},
	{ "http-keep-alive", &config.keep_alive, parse_bool, 0, 0},
	{ "http-proxy", &config.http_proxy, parse_string, 1, 0},
	{ "https-proxy", &config.https_proxy, parse_string, 1, 0},
	{ "keep-session-cookies", &config.keep_session_cookies, parse_bool, 0, 0},
	{ "load-cookies", &config.load_cookies, parse_string, 1, 0},
	{ "max-redirect", &config.max_redirect, parse_integer, 1, 0},
	{ "n", NULL, parse_n_option, 1, 'n'}, // special Wget compatibility option
	{ "num-threads", &config.num_threads, parse_integer, 1, 0},
	{ "output-document", &config.output_document, parse_string, 1, 'O'},
	{ "output-file", &config.logfile, parse_string, 1, 'o'},
	{ "private-key", &config.private_key, parse_string, 1, 0},
	{ "private-key-type", &config.private_key_type, parse_cert_type, 1, 0},
	{ "protocol-directories", &config.protocol_directories, parse_bool, 0, 0},
	{ "quiet", &config.quiet, parse_bool, 0, 'q'},
	{ "random-file", &config.random_file, parse_string, 1, 0},
	{ "read-timeout", &config.read_timeout, parse_timeout, 1, 0},
	{ "recursive", &config.recursive, parse_bool, 0, 'r'},
	{ "save-cookies", &config.save_cookies, parse_string, 1, 0},
	{ "secure-protocol", &config.secure_protocol, parse_string, 1, 0},
	{ "server-response", &config.server_response, parse_bool, 0, 'S'},
	{ "span-hosts", &config.span_hosts, parse_bool, 0, 'H'},
	{ "spider", &config.spider, parse_bool, 0, 0},
	{ "strict-comments", &config.strict_comments, parse_bool, 0, 0},
	{ "timeout", NULL, parse_timeout, 1, 'T'},
	{ "timestamping", &config.timestamping, parse_bool, 0, 'N'},
	{ "use-server-timestamp", &config.use_server_timestamps, parse_bool, 0, 0},
	{ "user-agent", &config.user_agent, parse_string, 1, 'U'},
	{ "verbose", &config.verbose, parse_bool, 0, 'v'},
	{ "version", NULL, print_version, 0, 'V'}
};

static int PURE NONNULL_ALL opt_compare(const void *key, const void *option)
{
	return strcmp((const char *)key, ((const option_t)option)->long_name);
}

static int NONNULL(1) set_long_option(const char *name, const char *value)
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
		strlcpy(namebuf, name, p - name + 1);
		name = namebuf;
		value = p + 1;
	}

	opt = bsearch(name, options, countof(options), sizeof(options[0]), opt_compare);

	if (!opt)
		err_printf_exit(_("Unknown option '%s'\n"), name);

	if (name != namebuf && opt->parser == parse_bool)
		value = NULL;

	log_printf("name=%s value=%s invert=%d\n", opt->long_name, value, invert);

	if (opt->parser == parse_string && invert) {
		// allow no-<string-option> to set value to NULL
		if (value && name == namebuf)
			err_printf_exit(_("Option 'no-%s' doesn't allow an argument\n"), name);

		xfree(*((const char **)opt->var));
	}
	else {
		if (value && !opt->args && opt->parser != parse_bool)
			err_printf_exit(_("Option '%s' doesn't allow an argument\n"), name);

		if (opt->args) {
			if (!value)
				err_printf_exit(_("Missing argument for option '%s'\n"), name);

			opt->parser(opt, NULL, value);

			if (name != namebuf)
				ret = opt->args;
		}
		else {
			if (opt->parser == parse_bool) {
				opt->parser(opt, NULL, value);

				if (invert)
					*((char *)opt->var) = !*((char *)opt->var); // invert boolean value
			} else
				opt->parser(opt, NULL, NULL);
		}
	}

	return ret;
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

static void NONNULL(1) _read_config(const char *cfgfile, int expand)
{
	static int level; // level of recursions to prevent endless include loops
	FILE *fp;
	char *buf = NULL, linebuf_static[1024], *linep;
	char name[64];
	int append = 0, pos, found;
	size_t bufsize = 0, linelen = 0;
	ssize_t len;
	buffer_t linebuf;

/*
	if (expand) {
		#include <wordexp.h>
		// do tilde, wildcard, command and variable expansion
		wordexp_t wp;
		struct stat st;

		if (wordexp(cfgfile, &wp, 0) == 0) {
			size_t it;

			for (it = 0; it < wp.we_wordc; it++) {
				if (stat(wp.we_wordv[it], &st) == 0 && S_ISREG(st.st_mode))
					_read_config(wp.we_wordv[it], 0);
			}
			wordfree(&wp);
		} else
			err_printf(_("Failed to expand %s\n"), cfgfile);

		return;
	}
*/

	if (expand) {
		glob_t globbuf;
//		struct stat st;
		int flags = GLOB_MARK;

#ifdef GLOB_TILDE
		flags |= GLOB_TILDE;
#endif

		if (glob(cfgfile, flags, NULL, &globbuf) == 0) {
			size_t it;

			for (it = 0; it < globbuf.gl_pathc; it++) {
				if (globbuf.gl_pathv[it][strlen(globbuf.gl_pathv[it])-1] != '/') {
				// if (stat(globbuf.gl_pathv[it], &st) == 0 && S_ISREG(st.st_mode)) {
					if (++level > 20)
						err_printf_exit(_("Config file recursion detected in %s\n"), cfgfile);

					_read_config(globbuf.gl_pathv[it], 0);

					level--;
				}
			}
			globfree(&globbuf);

		} else {
			if (++level > 20)
				err_printf_exit(_("Config file recursion detected in %s\n"), cfgfile);

			_read_config(cfgfile, 0);
			
			level--;
		}
		
		return;
	}

	buffer_init(&linebuf, linebuf_static, sizeof(linebuf_static));

	if ((fp = fopen(cfgfile, "r")) == NULL) {
		err_printf(_("Failed to open %s\n"), cfgfile);
		return;
	}

	log_printf(_("Reading %s\n"), cfgfile);
	while ((len = getline(&buf, &bufsize, fp)) >= 0) {
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
				buffer_memcat(&linebuf, linep, len - 1);
			} else {
				buffer_memcpy(&linebuf, linep, len - 1);
				append = 1;
			}
			continue;
		} else if (append) {
			buffer_strcat(&linebuf, linep);
			append = 0;
			linep = linebuf.data;
			linelen = linebuf.length;
		}

		if (sscanf(linep, " %63[A-Za-z0-9-] %n", name, &pos) >= 1) {
			if (linep[pos] == '=') {
				// option, e.g. debug=y
				found = 1;
				pos++;
			} else
				found = 2; // statement (e.g. include ".wgetrc.d") or boolean option without value (e.g. no-recursive)
		} else {
			err_printf(_("Failed to parse: '%s'\n"), linep);
			continue;
		}

		if (found) {
			char *val = linep + pos;
			int vallen = linelen - pos, quote;

			if (vallen >= 2 && ((quote = *val) == '\"' || quote == '\'')) {
				char *src = val + 1, *dst = val, c;

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

			if (found == 1) {
				// log_printf("%s = %s\n",name,val);
				set_long_option(name, val);
			} else {
				// log_printf("%s %s\n",name,val);
				if (!strcmp(name, "include")) {
					if (++level > 20)
						err_printf_exit(_("Config file recursion detected in %s\n"), cfgfile);

					_read_config(val, 1);

					level--;
				} else {
					set_long_option(name, NULL);
				}
			}
		}

		linelen = 0;
	}

	buffer_deinit(&linebuf);
	xfree(buf);
	fclose(fp);

	if (append) {
		err_printf(_("Failed to parse last line in '%s'\n"), cfgfile);
	}
}

static void read_config(void)
{
#ifdef GLOBAL_CONFIG_FILE
	_read_config(GLOBAL_CONFIG_FILE, 1);
#else
	_read_config("~/.mgetrc", 1);
#endif
}

static int NONNULL(2) parse_command_line(int argc, const char *const *argv)
{
	static short shortcut_to_option[128];
	size_t it;
	int n;

	// init the short option lookup table
	if (!shortcut_to_option[0]) {
		for (it = 0; it < countof(options); it++) {
			if (options[it].short_name > 0)
				shortcut_to_option[(unsigned char)options[it].short_name] = it + 1;
		}
	}

	// I like the idea of getopt() but not it's implementation (e.g. global variables).
	// Therefore I implement my own getopt() behaviour.
	for (n = 1; n < argc; n++) {
		const char *argp = argv[n];

		if (argp[0] != '-')
			return n;

		if (argp[1] == '-') {
			// long option
			if (argp[2] == 0)
				return n + 1;

			n += set_long_option(argp + 2, n < argc - 1 ? argv[n+1] : NULL);

		} else if (argp[1]) {
			// short option(s)
			int pos;

			for (pos = 1; argp[pos]; pos++) {
				option_t opt;
				int idx;

				if (isalnum(argp[pos]) && (idx = shortcut_to_option[(unsigned char)argp[pos]])) {
					opt = &options[idx - 1];
//					info_printf("opt=%p [%c]\n",(void *)opt,argp[pos]);
//					info_printf("name=%s\n",opt->long_name);
					if (opt->args) {
						const char *val;

						if (!argp[pos + 1] && argc <= n + opt->args)
							err_printf_exit(_("Missing argument(s) for option '-%c'\n"), argp[pos]);
						val = argp[pos + 1] ? argp + pos + 1 : argv[++n];
						n += opt->parser(opt, &argv[n], val);
						break;
/*
					}
					else if (opt->parser == parse_bool) {
						const char *val;

						if (argp[pos + 1]) {
							opt->parser(opt, &argv[n], argp + pos + 1);
							break;
						} else if (argc > n + opt->args && argv[n+1][0] != '-')
							val = argv[++n];
						else
							val = NULL;

						opt->parser(opt, &argv[n], val);
*/
					} else
						opt->parser(opt, &argv[n], NULL);
				} else
					err_printf_exit(_("Unknown option '-%c'\n"), argp[pos]);
			}
		}
	}

	return n;
}

// read config, parse CLI options, check values, set module options
// and return the number of arguments consumed

int init(int argc, const char *const *argv)
{
	int n, truncated = 1;

	// the following strdup's are just needed for reallocation/freeing purposes to
	// satisfy valgrind
	config.user_agent = strdup(config.user_agent);
	config.secure_protocol = strdup(config.secure_protocol);
	config.ca_directory = strdup(config.ca_directory);
	config.http_proxy = strdup_null(getenv("http_proxy"));
	config.https_proxy = strdup_null(getenv("https_proxy"));

	// this is a special case for switching on debugging before any config file is read
	if (argc >= 2 && (!strcmp(argv[1],"-d") || !strcmp(argv[1],"--debug"))) {
		config.debug = 1;
	}

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

		truncated = 1;
	}

	// read global config and user's config
	// settings in user's config override global settings
	read_config();

	// now read command line options which override the settings of the config files
	n = parse_command_line(argc, argv);

	// truncate logfile, if not in append mode
	if (config.logfile_append) {
		config.logfile = config.logfile_append;
		config.logfile_append = NULL;
	}
	else if (config.logfile && strcmp(config.logfile,"-") && !truncated) {
		int fd = open(config.logfile, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}

	// check for correct settings
	if (config.num_threads < 1)
		config.num_threads = 1;

	// truncate output document
	if (config.output_document && strcmp(config.output_document,"-")) {
		int fd = open(config.output_document, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}

	http_set_http_proxy(config.http_proxy);
	http_set_https_proxy(config.https_proxy);
	xfree(config.http_proxy);
	xfree(config.https_proxy);

	if (config.cookies && config.cookie_suffixes)
		cookie_load_public_suffixes(config.cookie_suffixes);

	if (config.load_cookies)
		cookie_load(config.load_cookies);

	// set module specific options
	tcp_set_debug(config.debug);
	tcp_set_timeout(NULL, config.read_timeout);
	tcp_set_connect_timeout(config.connect_timeout);
	tcp_set_dns_timeout(config.dns_timeout);
	tcp_set_dns_caching(config.dns_caching);
	ssl_set_check_certificate(config.check_certificate);

	return n;
}

// just needs to be called to free all allocated storage on exit
// for valgrind testing

void deinit(void)
{
	tcp_set_dns_caching(0); // frees DNS cache

	xfree(config.cookie_suffixes);
	xfree(config.load_cookies);
	xfree(config.save_cookies);
	xfree(config.logfile);
	xfree(config.logfile_append);
	xfree(config.user_agent);
	xfree(config.output_document);
	xfree(config.ca_cert);
	xfree(config.ca_directory);
	xfree(config.cert_file);
	xfree(config.egd_file);
	xfree(config.private_key);
	xfree(config.random_file);
	xfree(config.secure_protocol);

	http_set_http_proxy(NULL);
	http_set_https_proxy(NULL);
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
			err_printf("%s: Failed to find option '%s'\n", __func__, options[it].long_name);
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
				err_printf("%s: Failed to parse bool short option #%zu (=%d)\n", __func__, it, config.recursive);
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
				err_printf("%s: Failed to parse bool long option #%zu (%d)\n", __func__, it, config.recursive);
				ret = 1;
			}

			config.recursive = 2; // invalid bool value
			parse_command_line(3, test_bool[it].argv);
			if (config.recursive != test_bool[it].result) {
				err_printf("%s: Failed to parse bool long option #%zu (%d)\n", __func__, it, config.recursive);
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
				err_printf("%s: Failed to parse timeout short option #%zu (=%d)\n", __func__, it, config.dns_timeout);
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
				err_printf("%s: Failed to parse timeout long option #%zu (%d)\n", __func__, it, config.dns_timeout);
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
			if (null_strcmp(config.user_agent, test_string_short[it].result)) {
				err_printf("%s: Failed to parse string short option #%zu (=%s)\n", __func__, it, config.user_agent);
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
			if (null_strcmp(config.user_agent, test_string[it].result)) {
				err_printf("%s: Failed to parse string short option #%zu (=%s)\n", __func__, it, config.user_agent);
				ret = 1;
			}
		}

		// restore config values
		xfree(config.user_agent);
		config.user_agent = user_agent;
	}

	return ret;
}
