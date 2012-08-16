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
 * - add a default value for your variable in the 'config' initializer (in this file)
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
#include <sys/stat.h>

#include "xalloc.h"
#include "utils.h"
#include "log.h"
#include "net.h"
#include "gnutls.h"
#include "options.h"

typedef struct option *option_t; // forward declaration

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
		"  -V, --version           Display the version of Wget and exit.\n"
		"  -h, --help              Print this help.\n"
		"  -v, --verbose           Print more messages. (default: on)\n"
		"  -q, --quiet             Print no messages except debugging messages. (default: off)\n"
		"  -d, --debug             Print debugging messages. (default: off)\n"
		"  -o  --output-file       File where messages are printed to.\n"
		" \n"
		"Download:\n"
		"  -r  --recursive         Recursive download. (default: off)\n"
		"  -H  --span-hosts        Span hosts that where not given on the command line. (default: off)\n"
		"      --num-threads       Max. concurrent download threads. (default: 5)\n"
		"      --max-redirect      Max. number of redirections to follow. (default: 20)\n"
		"  -T  --timeout           General network timeout in seconds.\n"
		"      --dns-timeout       DNS lookup timeout in seconds.\n"
		"      --connect-timeout   Connect timeout in seconds.\n"
		"      --read-timeout      Read and write timeout in seconds.\n"
		"      --dns-caching       Enable DNS cache (default: on).\n"
		" \n"
		"HTTP/HTTPS related options:\n"
		"  -U  --user-agent        Set User-Agent: header in requests.\n"
		"      --check-certificate Check the server's certificate. (default: on)\n"
		" \n"
		);

	exit(0);
}

static int parse_integer(option_t opt, UNUSED const char *const *argv, const char *val)
{
	*((int *)opt->var) = atoi(val);

	return 0;
}

static int parse_string(option_t opt, UNUSED const char *const *argv, const char *val)
{
	// the strdup'ed string will be released on program exit
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

// default values for config options (if not 0 or NULL)
struct config
config = {
	.connect_timeout = -1,
	.dns_timeout = -1,
	.read_timeout = -1,
	.max_redirect = 20,
	.num_threads = 5,
	.dns_caching = 1,
	.user_agent = "Mget/"MGET_VERSION,
	.verbose = 1,
	.check_certificate=1
};

static struct option options[] = {
	// long name, config variable, parse function, number of arguments, short name
	// leave the entries in alphabetical order of 'long_name' !
	{ "connect-timeout", &config.connect_timeout, parse_timeout, 1, 0},
	{ "check-certificate", &config.check_certificate, parse_bool, 0, 0},
	{ "debug", &config.debug, parse_bool, 0, 'd'},
	{ "dns-cache", &config.dns_caching, parse_bool, 0, 0},
	{ "dns-timeout", &config.dns_timeout, parse_timeout, 1, 0},
	{ "help", NULL, print_help, 0, 'h'},
	{ "max-redirect", &config.max_redirect, parse_integer, 1, 0},
	{ "num-threads", &config.num_threads, parse_integer, 1, 0},
	{ "output-file", &config.logfile, parse_string, 1, 'o'},
	{ "quiet", &config.quiet, parse_bool, 0, 'q'},
	{ "read-timeout", &config.read_timeout, parse_timeout, 1, 0},
	{ "recursive", &config.recursive, parse_bool, 0, 'r'},
	{ "span-hosts", &config.span_hosts, parse_bool, 0, 'H'},
	{ "timeout", NULL, parse_timeout, 1, 'T'},
	{ "user-agent", &config.user_agent, parse_string, 1, 'U'},
	{ "verbose", &config.verbose, parse_bool, 0, 'v'},
	{ "version", NULL, print_version, 0, 'V'}
};

static int opt_compare(const void *key, const void *option)
{
	return strcmp((const char *)key, ((const option_t)option)->long_name);
}

static int set_long_option(const char *name, const char *value)
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

	// log_printf("opt=%p pos=%d\n",opt,pos);
	log_printf("name=%s value=%s\n",opt->long_name,value);

	if (value && !opt->args && opt->parser != parse_bool)
		err_printf_exit(_("Option '%s' doesn't allow an argument\n"), name);

	if (opt->args) {
		if (!value)
			err_printf_exit(_("Missing argument for option '%s'\n"), name);
		opt->parser(opt, NULL, value);
		if (name != namebuf)
			ret = opt->args;
	} else {
		if (opt->parser == parse_bool && value) {
			opt->parser(opt, NULL, value);
		} else
			opt->parser(opt, NULL, NULL);
	}

	if (opt->parser == parse_bool) {
		if (invert)
			*((char *)opt->var) = !*((char *)opt->var); // invert boolean value
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

static void _read_config(const char *cfgfile, int expand)
{
	FILE *fp;
	char *buf = NULL, linebuf[1024], *line = linebuf, *linep;
	char name[64];
	int append = 0, pos, found;
	size_t bufsize = 0, linelen = 0, linesize = sizeof(linebuf);
	ssize_t len;
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
				if (globbuf.gl_pathv[it][strlen(globbuf.gl_pathv[it])-1] != '/')
				// if (stat(globbuf.gl_pathv[it], &st) == 0 && S_ISREG(st.st_mode))
					_read_config(globbuf.gl_pathv[it], 0);
			}
			globfree(&globbuf);

		} else
			_read_config(cfgfile, 0);
		
		return;
	}

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

		if (append || linep[len - 1] == '\\') {
			// append line to last one
			if (linelen + len >= linesize) {
				// don't use realloc here since it copies 'linesize' bytes,
				// but we just need 'linelen' bytes
				char *tmp = xmalloc((linesize *= 2));
				if (line) {
					memcpy(tmp, line, linelen);
					if (line != linebuf)
						xfree(line);
				}
				line = tmp;
			}
			strcpy(line + linelen, linep);
			linelen += len;
			linep = line;

			if (linep[linelen - 1] == '\\') {
				linep[--linelen] = 0;
				append = 1;
				continue;
			} else
				append = 0;
		} else {
			linelen = len;
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
					_read_config(val, 1);
				} else {
					set_long_option(name, NULL);
				}
			}
		}

		linelen = 0;
	}
	if (line != linebuf)
		xfree(line);
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

static int parse_command_line(int argc, const char *const *argv)
{
	static short shortcut_to_option[128];
	size_t it;
	int n;

	// init the short option lookup table
	for (it = 0; it < countof(options); it++) {
		if (options[it].short_name > 0)
			shortcut_to_option[(unsigned char)options[it].short_name] = it + 1;
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
					// info_printf("opt=%p [%c]\n",opt,argp[pos]);
					// info_printf("name=%s\n",opt->long_name);
					if (opt->args) {
						const char *val;

						if (!argp[pos + 1] && argc <= n + opt->args)
							err_printf_exit(_("Missing argument(s) for option '-%c'\n"), argp[pos]);
						val = argp[pos + 1] ? argp + pos + 1 : argv[++n];
						n += opt->parser(opt, &argv[n], val);
						break;
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
	int n;

	// this is a special case for switching on debugging before any config file is read
	if (argc >= 2 && (!strcmp(argv[1],"-d") || !strcmp(argv[1],"--debug"))) {
		config.debug = 1;
	}

	// read global config and user's config
	// settings in user's config override global settings
	read_config();

	// now read command line options which override the settings of the config files
	n = parse_command_line(argc, argv);

	// check for correct settings
	if (config.num_threads < 1)
		config.num_threads = 1;

	// set module specific options
	tcp_set_dns_caching(config.dns_caching);
	ssl_set_check_certificate(config.check_certificate);

	return n;
}
