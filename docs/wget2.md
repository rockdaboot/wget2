# Wget2 User Manual

* [Name](#Name)
* [Synopsis](#Synopsis)
* [Description](#Description)
* [Options](#Options)
  * [Option Syntax](#Option Syntax)
  * [Basic Startup Options](#Basic Startup Options)
  * [Logging and Input File Options](#Logging and Input File Options)
  * [Download Options](#Download Options)
  * [Directory Options](#Directory Options)
  * [HTTP Options](#HTTP Options)
  * [HTTPS (SSL/TLS) Options](#HTTPS Options)
  * [Recursive Retrieval Options](#Recursive Retrieval Options)
  * [Recursive Accept/Reject Options](#Recursive Accept/Reject Options)
  * [Plugin Options](#Plugin Options)
* [Environment](#Environment)
* [Exit Status](#Exit Status)
* [Startup File](#Startup File)
* [Bugs](#Bugs)
* [Author](#Author)
* [Copyright](#Copyright)


# <a name="Name"/>Name

  Wget2 - a recursive metalink/file/website downloader.


# <a name="Synopsis"/>Synopsis

  `wget2 [options]... [URL]...`


# <a name="Description"/>Description

  GNU Wget2 is a free utility for non-interactive download of files from the Web.  It supports HTTP and HTTPS
  protocols, as well as retrieval through HTTP(S) proxies.

  Wget2 is non-interactive, meaning that it can work in the background, while the user is not logged on.  This allows
  you to start a retrieval and disconnect from the system, letting Wget2 finish the work.  By contrast, most of the Web
  browsers require constant user's presence, which can be a great hindrance when transferring a lot of data.

  Wget2 can follow links in HTML, XHTML, CSS, RSS, Atom and sitemap files to create local versions of remote web sites,
  fully recreating the directory structure of the original site.  This is sometimes referred to as
  _recursive downloading_.  While doing that, Wget2 respects the Robot Exclusion Standard (_/robots.txt_).  Wget2 can be
  instructed to convert the links in downloaded files to point at the local files, for offline viewing.

  Wget2 has been designed for robustness over slow or unstable network connections; if a download fails due to a network
  problem, it will keep retrying until the whole file has been retrieved.  If the server supports partial downloads, it
  may continue the download from where it left off.


# <a name="Options"/>Options

## <a name="Option Syntax"/>Option Syntax

  Every option has a long form and sometimes also a short one.
  Long options are more convenient to remember, but take time to type.
  You may freely mix different option styles. Thus you may write:

      wget2 -r --tries=10 https://example.com/ -o log

  The space between the option accepting an argument and the argument may be omitted.  Instead of `-o log` you can write
  `-olog`.

  You may put several options that do not require arguments together, like:

      wget2 -drc <URL>

  This is equivalent to:

      wget2 -d -r -c <URL>

  Since the options can be specified after the arguments, you may terminate them with `--`.  So the following will try to
  download URL `-x`, reporting failure to `log`:

      wget2 -o log -- -x

  The options that accept comma-separated lists all respect the convention that prepending `--no-` clears its
  value.  This can be useful to clear the `.wget2rc` settings.  For instance, if your `.wget2rc` sets `exclude-directories`
  to `/cgi-bin`, the following example will first reset it, and then set it to exclude `/priv` and `/trash`.  You can
  also clear the lists in `.wget2rc`.

      wget2 --no-exclude-directories -X /priv,/trash

  Most options that do not accept arguments are boolean options, so named because their state can be captured with a
  yes-or-no ("boolean") variable.  A boolean option is either affirmative or negative (beginning with `--no-`).
  All such options share several properties.

  Affirmative options can be negated by prepending the `--no-` to the option name; negative options can be negated by
  omitting the `--no-` prefix.  This might seem superfluous - if the default for an affirmative option is to not do
  something, then why provide a way to explicitly turn it off?  But the startup file may in fact change the default.
  For instance, using `timestamping = on` in `.wget2rc` makes Wget2 download updated files only.
  Using `--no-timestamping` is the only way to restore the factory default from the command line.


## <a name="Basic Startup Options"/>Basic Startup Options

### `-V`, `--version`

  Display the version of Wget2.

### `-h`, `--help`

  Print a help message describing all of Wget2's command-line options.

### `-b`, `--background`

Go to background immediately after startup. If no output file is specified via the `-o`, output is redirected to `wget-log`.

### `-e`, `--execute=command`

  Execute command as if it were a part of `.wget2rc`.  A command thus invoked will be executed after the commands in `.wget2rc`, thus
  taking precedence over them.  If you need to specify more than one wget2rc command, use multiple instances of `-e`.

### `--hyperlink`

  Hyperlink names of downloaded files so that they can opened from the terminal by clicking on them.  Only a few terminal emulators
  currently support hyperlinks.  Enable this option if you know your terminal supports hyperlinks.

## <a name="Logging and Input File Options"/>Logging and Input File Options

### `-o`, `--output-file=logfile`

  Log all messages to `logfile`.  The messages are normally reported to standard error.

### `-a`, `--append-output=logfile`

  Append to `logfile`. This is the same as `-o`, only it appends to `logfile` instead of overwriting the old log file. If `logfile`
  does not exist, a new file is created.

### `-d`, `--debug`

  Turn on debug output, meaning various information important to the developers of Wget2 if it does not work properly. Your
  system administrator may have chosen to compile Wget2 without debug support, in which case `-d` will not work. Please note that
  compiling with debug support is always safe, Wget2 compiled with the debug support will not print any debug info unless
  requested with `-d`.

### `-q`, `--quiet`

  Turn off Wget2's output.

### `-v`, `--verbose`

  Turn on verbose output, with all the available data. The default output is verbose.

### `-nv`, `--no-verbose`

  Turn off verbose without being completely quiet (use `-q` for that), which means that error messages and basic information still
  get printed.

### `--report-speed=type`

  Output bandwidth as `type`. The only accepted values are `bytes` (which is set by default) and `bits`. This option only works if
  `--progress=bar` is also set.

### `-i`, `--input-file=file`

  Read URLs from a local or external file. If `-` is specified as file, URLs are read from the standard input.
  Use `./-` to read from a file literally named `-`.

  If this function is used, no URLs need be present on the command line.  If there are URLs both on the command line and in an
  input file, those on the command lines will be the first ones to be retrieved. `file` is expected to contain one URL per line,
  except one of the `--force-` options specifies a different format.

  If you specify `--force-html`, the document will be regarded as HTML.  In that case you may have problems with relative
  links, which you can solve either by adding `<base href="url">` to the documents or by specifying `--base=url` on the command
  line.

  If you specify `--force-css`, the document will be regarded as CSS.

  If you specify `--force-sitemap`, the document will be regarded as XML sitemap.

  If you specify `--force-atom`, the document will be regarded as Atom Feed.

  If you specify `--force-rss`, the document will be regarded as RSS Feed.

  If you specify `--force-metalink`, the document will be regarded as Metalink description.

  If you have problems with relative links, you should use `--base=url` on the command line.

### `-F`, `--force-html`

  When input is read from a file, force it to be treated as an HTML file.  This enables you to retrieve relative links from
  existing HTML files on your local disk, by adding "<base href="url">" to HTML, or using the `--base` command-line option.

### `--force-css`

  Read and parse the input file as CSS.  This enables you to retrieve links from existing CSS files on your local disk.
  You will need `--base` to handle relative links correctly.

### `--force-sitemap`

  Read and parse the input file as sitemap XML.  This enables you to retrieve links from existing sitemap files on your local disk.
  You will need `--base` to handle relative links correctly.

### `--force-atom`

  Read and parse the input file as Atom Feed XML.  This enables you to retrieve links from existing sitemap files on your local disk.
  You will need `--base` to handle relative links correctly.

### `--force-rss`

  Read and parse the input file as RSS Feed XML.  This enables you to retrieve links from existing sitemap files on your local disk.
  You will need `--base` to handle relative links correctly.

### `--force-metalink`

  Read and parse the input file as Metalink.  This enables you to retrieve links from existing Metalink files on your local disk.
  You will need `--base` to handle relative links correctly.

### `-B`, `--base=URL`

  Resolves relative links using URL as the point of reference, when reading links from an HTML file specified via the
  `-i`/`--input-file` option (together with a `--force`... option, or when the input file was fetched remotely from a server describing it as
  HTML, CSS, Atom or RSS). This is equivalent to the presence of a "BASE" tag in the HTML input file, with URL as the value for the "href"
  attribute.

  For instance, if you specify `https://example.com/bar/a.html` for URL, and Wget2 reads `../baz/b.html` from the input file, it would be
  resolved to `https://example.com/baz/b.html`.

### `--config=FILE`

  Specify the location of configuration files you wish to use. If you specify more than one file, either by using a
  comma-separated list or several `--config` options, these files are read in left-to-right order.
  The files given in `$SYSTEM_WGET2RC` and (`$WGET2RC` or `~/.wget2rc`) are read in that order and then the user-provided
  config file(s). If set, `$WGET2RC` replaces `~/.wget2rc`.

  `--no-config` empties the internal list of config files.
  So if you want to prevent reading any config files, give `--no-config` on the command line.

  `--no-config` followed by `--config=file` just reads `file` and skips reading the default config files.

  Wget will attempt to tilde-expand filenames written in the configuration file on supported platforms.
  To use a file that starts with the character literal '~', use "./~" or an absolute path.

### `--rejected-log=logfile` [Not implemented yet]

  Logs all URL rejections to logfile as comma separated values.  The values include the reason of rejection, the URL and the
  parent URL it was found in.

### `--local-db`

  Enables reading/writing to local database files (default: on).

  These are the files for `--hsts`, `--hpkp`, `--ocsp`, etc.

  With `--no-local-db` you can switch reading/writing off, e.g. useful for testing.

  This option does not influence the reading of config files.

### `--stats-dns=[FORMAT:]FILE`

  Save DNS stats in format `FORMAT`, in file `FILE`.

  `FORMAT` can be `human` or `csv`. `-` is shorthand for `stdout` and `h` is shorthand for `human`.

  The CSV output format is

  Hostname,IP,Port,Duration

    `Duration` is given in milliseconds.

### `--stats-tls=[FORMAT:]FILE`

  Save TLS stats in format `FORMAT`, in file `FILE`.

  `FORMAT` can be `human` or `csv`. `-` is shorthand for `stdout` and `h` is shorthand for `human`.

  The CSV output format is

  Hostname,TLSVersion,FalseStart,TFO,Resumed,ALPN,HTTPVersion,Certificates,Duration

    `TLSVersion` can be 1,2,3,4,5 for SSL3, TLS1.0, TLS1.1, TLS1.2 and TLS1.3. -1 means 'None'.

    `FalseStart` whether the connection used TLS False Start. -1 if not applicable.

    `TFO` whether the connection used TCP Fast Open. -1 is TFO was disabled.

    `Resumed` whether the TLS session was resumed or not.

    `ALPN` is the ALPN negotiation string.

    `HTTPVersion` is 0 for HTTP 1.1 and 1 is for HTTP 2.0.

    `Certificates` is the size of the server's certificate chain.

    `Duration` is given in milliseconds.

### `--stats-ocsp=[FORMAT:]FILE`

  Save OCSP stats in format `FORMAT`, in file `FILE`.

  `FORMAT` can be `human` or `csv`. `-` is shorthand for `stdout` and `h` is shorthand for `human`.

  The CSV output format is

  Hostname,Stapling,Valid,Revoked,Ignored

    `Stapling` whether an OCSP response was stapled or not.

    `Valid` how many server certificates were valid regarding OCSP.

    `Revoked` how many server certificates were revoked regarding OCSP.

    `Ignored` how many server certificates had been ignored or OCSP responses missing.


### `--stats-server=[FORMAT:]FILE`

  Save Server stats in format `FORMAT`, in file `FILE`.

  `FORMAT` can be `human` or `csv`. `-` is shorthand for `stdout` and `h` is shorthand for `human`.

  The CSV output format is

  Hostname,IP,Scheme,HPKP,NewHPKP,HSTS,CSP

    `Scheme` 0,1,2 mean `None`, `http`, `https`.

     `HPKP` values 0,1,2,3 mean 'No HPKP', 'HPKP matched', 'HPKP doesn't match', 'HPKP error'.

    `NewHPKP` whether server sent HPKP (Public-Key-Pins) header.

    `HSTS` whether server sent HSTS (Strict-Transport-Security) header.

    `CSP` whether server sent CSP (Content-Security-Policy) header.

### `--stats-site=[FORMAT:]FILE`

  Save Site stats in format `FORMAT`, in file `FILE`.

  `FORMAT` can be `human` or `csv`. `-` is shorthand for `stdout` and `h` is shorthand for `human`.

  The CSV output format is

  ID,ParentID,URL,Status,Link,Method,Size,SizeDecompressed,TransferTime,ResponseTime,Encoding,Verification

    `ID` unique ID for a stats record.

    `ParentID` ID of the parent document, relevant for `--recursive` mode.

    `URL` URL of the document.

    `Status` HTTP response code or 0 if not applicable.

    `Link` 1 means 'direkt link', 0 means 'redirection link'.

    `Method` 1,2,3 mean GET, HEAD, POST request type.

    `Size` size of downloaded body (theoretical value for HEAD requests).

    `SizeDecompressed` size of decompressed body (0 for HEAD requests).

    `TransferTime` ms between start of request and completed download.

    `ResponseTime` ms between start of request and first response packet.

    `Encoding` 0,1,2,3,4,5 mean server side compression was 'identity', 'gzip', 'deflate', 'lzma/xz', 'bzip2', 'brotli', 'zstd', 'lzip'

    `Verification` PGP verification status. 0,1,2,3 mean 'none',  'valid', 'invalid', 'bad', 'missing'.

## <a name="Download Options"/>Download Options

### `--bind-address=ADDRESS`

  When making client TCP/IP connections, bind to ADDRESS on the local machine.  ADDRESS may be specified as a hostname or IP
  address.  This option can be useful if your machine is bound to multiple IPs.

### `--bind-interface=INTERFACE`

  When making client TCP/IP connections, bind to INTERFACE on the local machine. INTERFACE may be specified as the name
  for a Network Interface.  This option can be useful if your machine has multiple Network Interfaces.
  However, the option works only when wget2 is run with elevated privileges
  (On GNU/Linux: root / sudo or `sudo setcap cap_net_raw+ep <path to wget|wget2>`).

### `-t`, `--tries=number`

  Set number of tries to number. Specify 0 or inf for infinite retrying.  The default is to retry 20 times, with the exception
  of fatal errors like "connection refused" or "not found" (404), which are not retried.

### `--retry-on-http-error=list`

  Specify a comma-separated list of HTTP codes in which Wget2 will retry the download. The elements of the list may contain
  wildcards. If an HTTP code starts with the character '!' it won't be downloaded. This is useful when trying to download
  something with exceptions. For example, retry every failed download if error code is not 404:

      wget2 --retry-on-http-error=*,\!404 https://example.com/

  Please keep in mind that "200" is the only forbidden code. If it is included on the status list Wget2 will ignore it. The
  max. number of download attempts is given by the `--tries` option.

### `-O`, `--output-document=file`

  The documents will not be written to the appropriate files, but all will be concatenated together and written to file.  If `-`
  is used as file, documents will be printed to standard output, disabling link conversion. Use `./-` to print to a file
  literally named `-`. To not get Wget2 status messages mixed with file content, use `-q` in combination with `-O-` (This is
  different to how Wget 1.x behaves).

  Using `-r` or `-p` with `-O` may not work as you expect: Wget2 won't just download the first file to file and then
  download the rest to their normal names: all downloaded content will be placed in file.

  A combination with `-nc` is only accepted if the given output file does not exist.

  When used along with the `-c` option, Wget2 will attempt to continue downloading the file whose name is passed to the option,
  irrespective of whether the actual file already exists on disk or not. This allows users to download a file with a
  temporary name alongside the actual file.

  Note that a combination with `-k` is only permitted when downloading a single document, as in that case it will just convert all
  relative URIs to external ones; `-k` makes no sense for multiple URIs when they're all being downloaded to a single file; `-k` can
  be used only when the output is a regular file.

  Compatibility-Note: Wget 1.x used to treat `-O` as analogous to shell redirection. Wget2 does not handle the option similarly.
  Hence, the file will not always be newly created. The file's timestamps will not be affected unless it is actually written to.
  As a result, both `-c` and `-N` options are now supported in conjunction with this option.

### `-nc`, `--no-clobber`

  If a file is downloaded more than once in the same directory, Wget2's behavior depends on a few options, including
  `-nc`.  In certain cases, the local file will be clobbered, or overwritten, upon repeated download.  In other cases
  it will be preserved.

  When running Wget2 without `-N`, `-nc`, `-r`, or `-p`, downloading the same file in the same directory will result in the
  original copy of file being preserved and the second copy being named file.1.  If that file is downloaded yet
  again, the third copy will be named file.2, and so on. (This is also the behavior with `-nd`, even if `-r` or `-p` are
  in effect.) Use `--keep-extension` to use an alternative file naming pattern.

  When `-nc` is specified, this behavior is suppressed, and Wget2 will refuse to download newer copies of
  file.  Therefore, ""no-clobber"" is actually a misnomer in this mode - it's not clobbering that's prevented (as
  the numeric suffixes were already preventing clobbering), but rather the multiple version saving that's
  prevented.

  When running Wget2 with `-r` or `-p`, but without `-N`, `-nd`, or `-nc`, re-downloading a file will result in the new copy
  simply overwriting the old.  Adding `-nc` will prevent this behavior, instead causing the original version to be
  preserved and any newer copies on the server to be ignored.

  When running Wget2 with `-N`, with or without `-r` or `-p`, the decision as to whether or not to download a newer copy
  of a file depends on the local and remote timestamp and size of the file. `-nc` may not be specified at the same
  time as `-N`.

  A combination with `-O`/`--output-document` is only accepted if the given output file does not exist.

  Note that when `-nc` is specified, files with the suffixes .html or .htm will be loaded from the local disk and
  parsed as if they had been retrieved from the Web.

### `--backups=backups`

  Before (over)writing a file, back up an existing file by adding a .1 suffix to the file name.  Such
  backup files are rotated to .2, .3, and so on, up to `backups` (and lost beyond that).

### `-c`, `--continue`

  Continue getting a partially-downloaded file.  This is useful when you want to finish up a download started by a
  previous instance of Wget2, or by another program.  For instance:

      wget2 -c https://example.com/tarball.gz

  If there is a file named `tarball.gz` in the current directory, Wget2 will assume that it is the first portion of the
  remote file, and will ask the server to continue the retrieval from an offset equal to the length of the local
  file.

  Note that you don't need to specify this option if you just want the current invocation of Wget2 to retry
  downloading a file should the connection be lost midway through.  This is the default behavior.  `-c` only affects
  resumption of downloads started prior to this invocation of Wget2, and whose local files are still sitting around.

  Without `-c`, the previous example would just download the remote file to `tarball.gz.1`, leaving the truncated
  `tarball.gz` file alone.

  If you use `-c` on a non-empty file, and it turns out that the server does not support
  continued downloading, Wget2 will refuse to start the download from scratch, which would effectively ruin existing
  contents.  If you really want the download to start from scratch, remove the file.

  If you use `-c` on a file which is of equal size as the one on the server, Wget2 will
  refuse to download the file and print an explanatory message.  The same happens when the file is smaller on the
  server than locally (presumably because it was changed on the server since your last download attempt). Because
  "continuing" is not meaningful, no download occurs.

  On the other side of the coin, while using `-c`, any file that's bigger on the server than locally will be
  considered an incomplete download and only "(length(remote) - length(local))" bytes will be downloaded and tacked
  onto the end of the local file.  This behavior can be desirable in certain cases. For instance, you can use
  `wget2 -c` to download just the new portion that's been appended to a data collection or log file.

  However, if the file is bigger on the server because it's been changed, as opposed to just appended to, you'll
  end up with a garbled file.  Wget2 has no way of verifying that the local file is really a valid prefix of the
  remote file.  You need to be especially careful of this when using `-c` in conjunction with `-r`, since every file
  will be considered as an "incomplete download" candidate.

  Another instance where you'll get a garbled file if you try to use `-c` is if you have a lame HTTP proxy that
  inserts a "transfer interrupted" string into the local file.  In the future a "rollback" option may be added to
  deal with this case.

  Note that `-c` only works with HTTP servers that support the "Range" header.

### `--start-pos=OFFSET`

  Start downloading at zero-based position `OFFSET`.  Offset may be expressed in bytes, kilobytes with the `k'
  suffix, or megabytes with the `m' suffix, etc.

  `--start-pos` has higher precedence over `--continue`.  When `--start-pos` and `--continue` are both specified, Wget2 will
  emit a warning then proceed as if `--continue` was absent.

  Server support for continued download is required, otherwise --start-pos cannot help.  See `-c` for details.

### `--progress=type`

  Select the type of the progress indicator you wish to use. Supported indicator types are `none` and `bar`.

  Type `bar` draws an ASCII progress bar graphics (a.k.a "thermometer" display) indicating the status of retrieval.

  If the output is a TTY, `bar` is the default. Else, the progress bar will be switched off, except when using `--force-progress`.

  The type 'dot' is currently not supported, but won't trigger an error to not break wget command lines.

  The parameterized types `bar:force` and `bar:force:noscroll` will add the effect of `--force-progress`.
  These are accepted for better wget compatibility.

### `--force-progress`

  Force Wget2 to display the progress bar in any verbosity.

  By default, Wget2 only displays the progress bar in verbose mode.  One may however, want Wget2 to display the
  progress bar on screen in conjunction with any other verbosity modes like `--no-verbose` or `--quiet`.  This is often
  a desired a property when invoking Wget2 to download several small/large files.  In such a case, Wget2 could simply
  be invoked with this parameter to get a much cleaner output on the screen.

  This option will also force the progress bar to be printed to stderr when used alongside the `--output-file` option.

### `-N`, `--timestamping`

  Turn on time-stamping.

### `--no-if-modified-since`

  Do not send If-Modified-Since header in `-N` mode. Send preliminary HEAD request instead. This has only effect in
  `-N` mode.

### `--no-use-server-timestamps`

  Don't set the local file's timestamp by the one on the server.

  By default, when a file is downloaded, its timestamps are set to match those from the remote file. This allows
  the use of `--timestamping` on subsequent invocations of Wget2. However, it is sometimes useful to base the local
  file's timestamp on when it was actually downloaded; for that purpose, the `--no-use-server-timestamps` option has
  been provided.

### `-S`, `--server-response`

  Print the response headers sent by HTTP servers.

### `--spider`

  When invoked with this option, Wget2 will behave as a Web spider, which means that it will not download the pages,
  just check that they are there.  For example, you can use Wget2 to check your bookmarks:

      wget2 --spider --force-html -i bookmarks.html

  This feature needs much more work for Wget2 to get close to the functionality of real web spiders.

### `-T seconds`, `--timeout=seconds`

  Set the network timeout to seconds seconds.  This is equivalent to specifying `--dns-timeout`, `--connect-timeout`,
  and `--read-timeout`, all at the same time.

  When interacting with the network, Wget2 can check for timeout and abort the operation if it takes too long.  This
  prevents anomalies like hanging reads and infinite connects.  The only timeout enabled by default is a 900-second
  read timeout.  Setting a timeout to 0 disables it altogether.  Unless you know what you are doing, it is best not
  to change the default timeout settings.

  All timeout-related options accept decimal values, as well as subsecond values.  For example, 0.1 seconds is a
  legal (though unwise) choice of timeout.  Subsecond timeouts are useful for checking server response times or for
  testing network latency.

### `--dns-timeout=seconds`

  Set the DNS lookup timeout to seconds seconds.  DNS lookups that don't complete within the specified time will
  fail.  By default, there is no timeout on DNS lookups, other than that implemented by system libraries.

### `--connect-timeout=seconds`

  Set the connect timeout to seconds seconds.  TCP connections that take longer to establish will be aborted.  By
  default, there is no connect timeout, other than that implemented by system libraries.

### `--read-timeout=seconds`

  Set the read (and write) timeout to seconds seconds.  The "time" of this timeout refers to idle time: if, at any
  point in the download, no data is received for more than the specified number of seconds, reading fails and the
  download is restarted.  This option does not directly affect the duration of the entire download.

  Of course, the remote server may choose to terminate the connection sooner than this option requires.  The
  default read timeout is 900 seconds.

### `--limit-rate=amount`

  Limit the download speed to amount bytes per second.  Amount may be expressed in bytes, kilobytes with the k
  suffix, or megabytes with the m suffix.  For example, `--limit-rate=20k` will limit the retrieval rate to 20KB/s.
  This is useful when, for whatever reason, you don't want Wget2 to consume the entire available bandwidth.

  This option allows the use of decimal numbers, usually in conjunction with power suffixes; for example,
  `--limit-rate=2.5k` is a legal value.

  Note that Wget2 implements the limiting by sleeping the appropriate amount of time after a network read that took
  less time than specified by the rate.  Eventually this strategy causes the TCP transfer to slow down to
  approximately the specified rate.  However, it may take some time for this balance to be achieved, so don't be
  surprised if limiting the rate doesn't work well with very small files.

### `-w seconds`, `--wait=seconds`

  Wait the specified number of seconds between the retrievals.  Use of this option is recommended, as it lightens
  the server load by making the requests less frequent.  Instead of in seconds, the time can be specified in
  minutes using the "m" suffix, in hours using "h" suffix, or in days using "d" suffix.

  Specifying a large value for this option is useful if the network or the destination host is down, so that Wget2
  can wait long enough to reasonably expect the network error to be fixed before the retry.  The waiting interval
  specified by this function is influenced by `--random-wait`, which see.

### `--waitretry=seconds`

  If you don't want Wget2 to wait between every retrieval, but only between retries of failed downloads, you can use
  this option.  Wget2 will use linear backoff, waiting 1 second after the first failure on a given file, then
  waiting 2 seconds after the second failure on that file, up to the maximum number of seconds you specify.

  By default, Wget2 will assume a value of 10 seconds.

### `--random-wait`

  Some web sites may perform log analysis to identify retrieval programs such as Wget2 by looking for statistically
  significant similarities in the time between requests. This option causes the time between requests to vary
  between 0.5 and 1.5 ### wait seconds, where wait was specified using the `--wait` option, in order to mask Wget2's
  presence from such analysis.

  A 2001 article in a publication devoted to development on a popular consumer platform provided code to perform
  this analysis on the fly.  Its author suggested blocking at the class C address level to ensure automated
  retrieval programs were blocked despite changing DHCP-supplied addresses.

  The `--random-wait` option was inspired by this ill-advised recommendation to block many unrelated users from a web
  site due to the actions of one.

### `--no-proxy[=exceptions]`

  If no argument is given, we try to stay backward compatible with Wget1.x and
  don't use proxies, even if the appropriate *_proxy environment variable is defined.

  If a comma-separated list of exceptions (domains/IPs) is given, these exceptions are accessed without
  using a proxy. It overrides the 'no_proxy' environment variable.

### `-Q quota`, `--quota=quota`

  Specify download quota for automatic retrievals.  The value can be specified in bytes (default), kilobytes (with
  k suffix), or megabytes (with m suffix).

  Note that quota will never affect downloading a single file.  So if you specify

      wget2 -Q10k https://example.com/bigfile.gz

  all of the `bigfile.gz` will be downloaded.  The same goes even when several URLs
  are specified on the command-line.  However, quota is respected when retrieving either recursively, or from an
  input file.  Thus you may safely type

      wget2 -Q2m -i sites

  download will be aborted when the quota is exceeded.

  Setting quota to `0` or to `inf` unlimits the download quota.

### `--restrict-file-names=modes`

  Change which characters found in remote URLs must be escaped during generation of local filenames.  Characters
  that are restricted by this option are escaped, i.e. replaced with %HH, where HH is the hexadecimal number that
  corresponds to the restricted character. This option may also be used to force all alphabetical cases to be
  either lower- or uppercase.

  By default, Wget2 escapes the characters that are not valid or safe as part of file names on your operating
  system, as well as control characters that are typically unprintable.  This option is useful for changing these
  defaults, perhaps because you are downloading to a non-native partition, or because you want to disable escaping
  of the control characters, or you want to further restrict characters to only those in the ASCII range of values.

  The modes are a comma-separated set of text values. The acceptable values are unix, windows, nocontrol, ascii,
  lowercase, and uppercase. The values unix and windows are mutually exclusive (one will override the other), as
  are lowercase and uppercase. Those last are special cases, as they do not change the set of characters that would
  be escaped, but rather force local file paths to be converted either to lower- or uppercase.

  When "unix" is specified, Wget2 escapes the character / and the control characters in the ranges 0--31 and
  128--159.  This is the default on Unix-like operating systems.

  When "windows" is given, Wget2 escapes the characters \, |, /, :, ?, ", *, <, >, and the control characters in the
  ranges 0--31 and 128--159.  In addition to this, Wget2 in Windows mode uses + instead of : to separate host and
  port in local file names, and uses @ instead of ? to separate the query portion of the file name from the rest.
  Therefore, a URL that would be saved as `www.xemacs.org:4300/search.pl?input=blah` in Unix mode would be saved as
  `www.xemacs.org+4300/search.pl@input=blah` in Windows mode.  This mode is the default on Windows.

  If you specify nocontrol, then the escaping of the control characters is also switched off. This option may make
  sense when you are downloading URLs whose names contain UTF-8 characters, on a system which can save and display
  filenames in UTF-8 (some possible byte values used in UTF-8 byte sequences fall in the range of values designated
  by Wget2 as "controls").

  The ascii mode is used to specify that any bytes whose values are outside the range of ASCII characters (that is,
  greater than 127) shall be escaped. This can be useful when saving filenames whose encoding does not match the
  one used locally.

### `-4`, `--inet4-only`, `-6`, `--inet6-only`

  Force connecting to IPv4 or IPv6 addresses.  With `--inet4-only` or `-4`, Wget2 will only connect to IPv4 hosts,
  ignoring AAAA records in DNS, and refusing to connect to IPv6 addresses specified in URLs.  Conversely, with
  `--inet6-only` or `-6`, Wget2 will only connect to IPv6 hosts and ignore A records and IPv4 addresses.

  Neither options should be needed normally.  By default, an IPv6-aware Wget2 will use the address family specified
  by the host's DNS record.  If the DNS responds with both IPv4 and IPv6 addresses, Wget2 will try them in sequence
  until it finds one it can connect to.  (Also see `--prefer-family` option described below.)

  These options can be used to deliberately force the use of IPv4 or IPv6 address families on dual family systems,
  usually to aid debugging or to deal with broken network configuration.  Only one of `--inet6-only` and `--inet4-only`
  may be specified at the same time.  Neither option is available in Wget2 compiled without IPv6 support.

### `--prefer-family=none/IPv4/IPv6`

  When given a choice of several addresses, connect to the addresses with specified address family first.  The
  address order returned by DNS is used without change by default.

  This avoids spurious errors and connect attempts when accessing hosts that resolve to both IPv6 and IPv4
  addresses from IPv4 networks.  For example, www.kame.net resolves to 2001:200:0:8002:203:47ff:fea5:3085 and to
  203.178.141.194.  When the preferred family is "IPv4", the IPv4 address is used first; when the preferred family
  is "IPv6", the IPv6 address is used first; if the specified value is "none", the address order returned by DNS is
  used without change.

  Unlike -4 and -6, this option doesn't inhibit access to any address family, it only changes the order in which
  the addresses are accessed.  Also note that the reordering performed by this option is stable. It doesn't affect
  order of addresses of the same family.  That is, the relative order of all IPv4 addresses and of all IPv6
  addresses remains intact in all cases.

### `--tcp-fastopen`

  Enable support for TCP Fast Open (TFO) (default: off).

  TFO reduces connection latency by 1 RT on "hot" connections (2nd+ connection to the same host in a certain amount of time).

  Currently this works on recent Linux and OSX kernels, on HTTP and HTTPS.

  The main reasons why TFO is disabled by default are
    - possible user tracking issues
    - possible issues with middle boxes that do not support TFO

  This article gives has more details about TFO than fits here: https://candrews.integralblue.com/2019/03/the-sad-story-of-tcp-fast-open/

### `--dns-cache-preload=file`

  Load a list of IP / Name tuples into the DNS cache.

  The format of `file` is like `/etc/hosts`: IP-address whitespace Name

  This allows to save domain name lookup time, which is a bottleneck in some use cases.
  Also, the use of HOSTALIASES (which is not portable) can be mimicked by this option.

### `--dns-cache`

  Enable DNS caching (default: on).

  Normally, Wget2 remembers the IP addresses it looked up from DNS so it doesn't have to
  repeatedly contact the DNS server for the same (typically small) set of hosts it retrieves from.
  This cache exists in memory only; a new Wget2 run will contact DNS again.

  However, it has been reported that in some situations it is not desirable to cache host names, even for the
  duration of a short-running application like Wget2.  With `--no-dns-cache` Wget2 issues a new DNS lookup (more
  precisely, a new call to "gethostbyname" or "getaddrinfo") each time it makes a new connection.  Please note that
  this option will not affect caching that might be performed by the resolving library or by an external caching
  layer, such as NSCD.

### `--retry-connrefused`

  Consider "connection refused" a transient error and try again.  Normally Wget2 gives up on a URL when it is unable
  to connect to the site because failure to connect is taken as a sign that the server is not running at all and
  that retries would not help.  This option is for mirroring unreliable sites whose servers tend to disappear for
  short periods of time.

### `--user=user`, `--password=password`

  Specify the username user and password password for HTTP file retrieval. This overrides the lookup of
  credentials in the .netrc file (`--netrc` is enabled by default). These parameters can be overridden using the
  `--http-user` and `--http-password` options for HTTP(S) connections.

  If neither `--http-proxy-user` nor `--http-proxy-password` is given these settings are also taken for proxy authentication.

### `--ask-password`

  Prompt for a password on the command line. Overrides the password set by `--password` (if any).

### `--use-askpass=command`

  Prompt for a user and password using the specified command. Overrides the user and/or password set by `--user`/`--password` (if any).

### `--no-iri`

  Turn off internationalized URI (IRI) support. Use `--iri` to turn it on. IRI support is activated by default.

  You can set the default state of IRI support using the "iri" command in `.wget2rc`. That setting may be overridden
  from the command line.

### `--local-encoding=encoding`

  Force Wget2 to use encoding as the default system encoding. That affects how Wget2 converts URLs specified as
  arguments from locale to UTF-8 for IRI support.

  Wget2 use the function "nl_langinfo()" and then the "CHARSET" environment variable to get the locale. If it fails,
  ASCII is used.

### `--remote-encoding=encoding`

  Force Wget2 to use encoding as the default remote server encoding.  That affects how Wget2 converts URIs found in
  files from remote encoding to UTF-8 during a recursive fetch. This options is only useful for IRI support, for
  the interpretation of non-ASCII characters.

  For HTTP, remote encoding can be found in HTTP "Content-Type" header and in HTML "Content-Type http-equiv" meta
  tag.

### `--input-encoding=encoding`

  Use the specified encoding for the URLs read from `--input-file`. The default is the local encoding.

### `--unlink`

  Force Wget2 to unlink file instead of clobbering existing file. This option is useful for downloading to the
  directory with hardlinks.

### `--cut-url-get-vars`

  Remove HTTP GET Variables from URLs.
  For example "main.css?v=123" will be changed to "main.css".
  Be aware that this may have unintended side effects, for example "image.php?name=sun" will be changed
  to "image.php". The cutting happens before adding the URL to the download queue.

### `--cut-file-get-vars`

  Remove HTTP GET Variables from filenames.
  For example "main.css?v=123" will be changed to "main.css".

  Be aware that this may have unintended side effects, for example "image.php?name=sun" will be changed
  to "image.php". The cutting happens when saving the file, after downloading.

  File names obtained from a "Content-Disposition" header are not affected by this setting (see `--content-disposition`),
  and can be a solution for this problem.

  When `--trust-server-names` is used, the redirection URL is affected by this setting.

### `--chunk-size=size`

  Download large files in multithreaded chunks. This switch specifies the size of the chunks, given in bytes if no other
  byte multiple unit is specified. By default it's set on 0/off.

### `--max-threads=number`

  Specifies the maximum number of concurrent download threads for a resource. The default is 5 but if you want to
  allow more or fewer this is the option to use.

### `-s`, `--verify-sig[=fail|no-fail]`

  Enable PGP signature verification (when not prefixed with `no-`). When enabled Wget2 will attempt
  to download and verify PGP signatures against their corresponding files. Any file downloaded that has a
  content type beginning with `application/` will cause Wget2 to request the signature for that file.

  The name of the signature file is computed by appending the extension to the full path of the file that
  was just downloaded. The extension used is defined by the `--signature-extensions` option.
  If the content type for the signature request is `application/pgp-signature`, Wget2 will attempt to
  verify the signature against the original file. By default, if a signature file cannot be found
  (I.E. the request for it gets a 404 status code) Wget2 will exit with an error code.

  This behavior can be tuned using the following arguments:
  * `fail`: This is the default, meaning that this is the value when you supply the flag without an argument.
    Indicates that missing signature files will cause Wget2 to exit with an error code.
  * `no-fail`: This value allows missing signature files. A 404 message will still be issued, but the program
    will exit normally (assuming no unrelated errors).

  Additionally, `--no-verify-sig` disables signature checking altogether
  `--no-verify-sig` does not allow any arguments.


### `--signature-extensions`

  Specify the file extensions for signature files, without the leading ".". You
  may specify multiple extensions as a comma separated list. All the provided
  extensions will be tried simultaneously when looking for the signature file. The
  default is "sig".

### `--gnupg-homedir`

  Specifies the gnupg home directory to use when verifying PGP signatures on downloaded files. The default for this is
  your system's default home directory.

### `--verify-save-failed`

  Instructs Wget2 to keep files that don't pass PGP signature validation. The default is to delete files that fail validation.

### `--xattr`

  Saves documents metadata as "user POSIX Extended Attributes" (default: on). This feature only works if the file system
  supports it. More info on https://freedesktop.org/wiki/CommonExtendedAttributes.

  Wget2 currently sets
  * user.xdg.origin.url
  * user.xdg.referrer.url
  * user.mime_type
  * user.charset

  To display the extended attributes of a file (Linux): `getfattr -d <file>`

### `--metalink`

  Follow/process metalink URLs without saving them (default: on).

  Metalink files describe downloads incl. mirrors, files, checksums, signatures.
  This allows chunked downloads, automatically taking the nearest mirrors, preferring the
  fastest mirrors and checking the download for integrity.

### `--fsync-policy`

  Enables disk syncing after each write (default: off).

### `--http2-request-window=number`

  Set max. number of parallel streams per HTTP/2 connection (default: 30).

### `--keep-extension`

  This option changes the behavior for creating a unique filename if a file already exists.

  The standard (default) pattern for file names is `<filename>.<N>`, the new pattern is
  `<basename>_<N>.<ext>`.

  The idea is to use such files without renaming when the use depends on the
  extension, like on Windows.

  This option doesn not change the behavior of `--backups`.


## <a name="Directory Options"/>Directory Options

### `-nd`, `--no-directories`

  Do not create a hierarchy of directories when retrieving recursively.  With this option turned on, all files will
  get saved to the current directory, without clobbering (if a name shows up more than once, the filenames will get
  extensions .n).

### `-x`, `--force-directories`

  The opposite of `-nd`: create a hierarchy of directories, even if one would not have been created otherwise.  E.g.
  `wget2 -x https://example.com/robots.txt` will save the downloaded file to `example.com/robots.txt`.

### `-nH`, `--no-host-directories`

  Disable generation of host-prefixed directories.  By default, invoking Wget2 with `-r https://example.com/` will
  create a structure of directories beginning with `example.com/`.  This option disables such behavior.

### `--protocol-directories`

  Use the protocol name as a directory component of local file names.  For example, with this option, `wget2 -r
  https://example.com` will save to `https/example.com/...` rather than just to `example.com/...`.

### `--cut-dirs=number`

  Ignore a number of directory components.  This is useful for getting a fine-grained control over the directory where
  recursive retrieval will be saved.

  Take, for example, the directory at https://example.com/pub/sub/.  If you retrieve it with `-r`, it will be
  saved locally under `example.com/pub/sub/`.  While the `-nH` option can remove the `example.com/` part, you
  are still stuck with `pub/sub/`.  This is where `--cut-dirs` comes in handy; it makes Wget2 not "see" a number
  of remote directory components.  Here are several examples of how `--cut-dirs` option works.
  ```
     No options        -> example.com/pub/sub/
     --cut-dirs=1      -> example.com/sub/
     --cut-dirs=2      -> example.com/
     -nH               -> pub/sub/
     -nH --cut-dirs=1  -> sub/
     -nH --cut-dirs=2  -> .
  ```
  If you just want to get rid of the directory structure, this option is similar to a combination of `-nd` and `-P`.
  However, unlike `-nd`, `--cut-dirs` does not lose with subdirectories. For instance, with `-nH --cut-dirs=1`, a `beta/`
  subdirectory will be placed to `sub/beta/`, as one would expect.

### `-P prefix`, `--directory-prefix=prefix`

  Set directory prefix to prefix.  The directory prefix is the directory where all other files and subdirectories
  will be saved to, i.e. the top of the retrieval tree.  The default is `.`, the current directory.
  If the directory `prefix` doesn't exist, it will be created.

## <a name="HTTP Options"/>HTTP Options

### `--default-page=name`

  Use name as the default file name when it isn't known (i.e., for URLs that end in a slash), instead of
  `index.html`.

### `--default-http-port=port`

  Set the default port for HTTP URLs (default: 80).

  This is mainly for testing purposes.

### `--default-https-port=port`

  Set the default port for HTTPS URLs (default: 443).

  This is mainly for testing purposes.

### `-E`, `--adjust-extension`

  If a file of type `application/xhtml+xml` or `text/html` is downloaded and the URL does not end with the regexp
  `\.[Hh][Tt][Mm][Ll]?`, this option will cause the suffix `.html` to be appended to the local filename.  This is
  useful, for instance, when you're mirroring a remote site that uses .asp pages, but you want the mirrored pages
  to be viewable on your stock Apache server.  Another good use for this is when you're downloading CGI-generated
  materials.  A URL like `https://example.com/article.cgi?25` will be saved as `article.cgi?25.html`.

  Note that filenames changed in this way will be re-downloaded every time you re-mirror a site, because Wget2 can't
  tell that the local `X.html` file corresponds to remote URL X (since it doesn't yet know that the URL produces
  output of type `text/html` or `application/xhtml+xml`.

  Wget2 will also ensure that any downloaded files of type `text/css` end in the suffix `.css`.

  At some point in the future, this option may well be expanded to include suffixes for other types of content,
  including content types that are not parsed by Wget.

### `--http-user=user`, `--http-password=password`

  Specify the user and password for HTTP authentication. According to the type of the challenge, Wget
  will encode them using either the "basic" (insecure), the "digest", or the Windows "NTLM" authentication scheme.

  If possible, put your credentials into `~/.netrc` (see also `--netrc` and `--netrc-file` options) or into `.wget2rc`.
  This is far more secure than using the command line which can be seen by any other user.
  If the passwords are really important, do not leave them lying in those files either. Edit the files and delete
  them after Wget2 has started the download.

  In `~/.netrc` passwords may be double quoted to allow spaces. Also, escape characters with a backslash if needed.
  A backslash in a password always needs to be escaped, so use `\\` instead of a single `\`.

  Also see `--use-askpass` and `--ask-password` for an interactive method to provide your password.

### `--http-proxy-user=user`, `--http-proxy-password=password`

  Specify the user and password for HTTP proxy authentication. See `--http-user` for details.

### `--http-proxy=proxies`

  Set comma-separated list of HTTP proxies. The environment variable 'http_proxy' will be overridden.

  Exceptions can be set via the environment variable 'no_proxy' or via `--no-proxy`.

### `--https-proxy=proxies`

  Set comma-separated list of HTTPS proxies. The environment variable 'https_proxy' will be overridden.

  Exceptions can be set via the environment variable 'no_proxy' or via `--no-proxy`.

### `--no-http-keep-alive`

  Turn off the "keep-alive" feature for HTTP(S) downloads.  Normally, Wget2 asks the server to keep the connection open
  so that, when you download more than one document from the same server, they get transferred over the same TCP
  connection.  This saves time and at the same time reduces the load on the server.

  This option is useful when, for some reason, persistent (keep-alive) connections don't work for you, for example
  due to a server bug or due to the inability of server-side scripts to cope with the connections.

### `--no-cache`

  Disable server-side cache.  In this case, Wget2 will send the remote server appropriate directives (Cache-Control: no-
  cache and Pragma: no-cache) to get the file from the remote service, rather than returning the cached version.  This is
  especially useful for retrieving and flushing out-of-date documents on proxy servers.

  Caching is allowed by default.

### `--no-cookies`

  Disable the use of cookies.  Cookies are a mechanism for maintaining server-side state.  The server sends the
  client a cookie using the "Set-Cookie" header, and the client responds with the same cookie upon further
  requests.  Since cookies allow the server owners to keep track of visitors and for sites to exchange this
  information, some consider them a breach of privacy.  The default is to use cookies; however, storing cookies is
  not on by default.

### `--load-cookies file`

  Load cookies from `file` before the first HTTP(S) retrieval.  file is a textual file in the format originally used by
  Netscape's cookies.txt file.

  You will typically use this option when mirroring sites that require that you be logged in to access some or all
  of their content.  The login process typically works by the web server issuing an HTTP cookie upon receiving and
  verifying your credentials.  The cookie is then resent by the browser when accessing that part of the site, and
  so proves your identity.

  Mirroring such a site requires Wget2 to send the same cookies your browser sends when communicating with the site.
  This is achieved by `--load-cookies`: simply point Wget2 to the location of the cookies.txt file, and it will send
  the same cookies your browser would send in the same situation.  Different browsers keep textual cookie files in
  different locations:

  "Netscape 4.x."
      The cookies are in ~/.netscape/cookies.txt.

  "Mozilla and Netscape 6.x."
      Mozilla's cookie file is also named cookies.txt, located somewhere under ~/.mozilla, in the directory of your
      profile.  The full path usually ends up looking somewhat like ~/.mozilla/default/some-weird-
      string/cookies.txt.

  "Internet Explorer."
      You can produce a cookie file Wget2 can use by using the File menu, Import and Export, Export Cookies.  This
      has been tested with Internet Explorer 5; it is not guaranteed to work with earlier versions.

  "Other browsers."
      If you are using a different browser to create your cookies, `--load-cookies` will only work if you can locate
      or produce a cookie file in the Netscape format that Wget2 expects.

  If you cannot use `--load-cookies`, there might still be an alternative.  If your browser supports a "cookie
  manager", you can use it to view the cookies used when accessing the site you're mirroring.  Write down the name
  and value of the cookie, and manually instruct Wget2 to send those cookies, bypassing the "official" cookie
  support:

      wget2 --no-cookies --header "Cookie: <name>=<value>"

### `--save-cookies file`

  Save cookies to `file` before exiting.  This will not save cookies that have expired or that have no expiry time
  (so-called "session cookies"), but also see `--keep-session-cookies`.

### `--keep-session-cookies`

  When specified, causes `--save-cookies` to also save session cookies.  Session cookies are normally not saved
  because they are meant to be kept in memory and forgotten when you exit the browser.  Saving them is useful on
  sites that require you to log in or to visit the home page before you can access some pages.  With this option,
  multiple Wget2 runs are considered a single browser session as far as the site is concerned.

  Since the cookie file format does not normally carry session cookies, Wget2 marks them with an expiry timestamp of
  0.  Wget2's `--load-cookies` recognizes those as session cookies, but it might confuse other browsers.  Also note
  that cookies so loaded will be treated as other session cookies, which means that if you want `--save-cookies` to
  preserve them again, you must use `--keep-session-cookies` again.

### `--cookie-suffixes=file`

  Load the public suffixes used for cookie checking from the given file.

  Normally, the underlying libpsl loads this data from a system file or it has the data built in.
  In some cases you might want to load an updated PSL, e.g. from https://publicsuffix.org/list/public_suffix_list.dat.

  The PSL allows to prevent setting of "super-cookies" that lead to cookie privacy leakage.
  More details can be found on https://publicsuffix.org/.

### `--ignore-length`

  Unfortunately, some HTTP servers (CGI programs, to be more precise) send out bogus "Content-Length" headers,
  which makes Wget2 go wild, as it thinks not all the document was retrieved.  You can spot this syndrome if Wget
  retries getting the same document again and again, each time claiming that the (otherwise normal) connection has
  closed on the very same byte.

  With this option, Wget2 will ignore the "Content-Length" header as if it never existed.

### `--header=header-line`

  Send header-line along with the rest of the headers in each HTTP request.  The supplied header is sent as-is,
  which means it must contain name and value separated by colon, and must not contain newlines.

  You may define more than one additional header by specifying `--header` more than once.

      wget2 --header='Accept-Charset: iso-8859-2' \
           --header='Accept-Language: hr'        \
             https://example.com/

  Specification of an empty string as the header value will clear all previous user-defined headers.

  This option can be used to override headers otherwise generated automatically.  This example
  instructs Wget2 to connect to localhost, but to specify `example.com` in the "Host" header:

      wget2 --header="Host: example.com" http://localhost/

### `--max-redirect=number`

  Specifies the maximum number of redirections to follow for a resource.  The default is 20, which is usually far
  more than necessary. However, on those occasions where you want to allow more (or fewer), this is the option to
  use.

### `--proxy-user=user`, `--proxy-password=password` [Not implemented, use `--http-proxy-password`]

  Specify the username user and password password for authentication on a proxy server.  Wget2 will encode them
  using the "basic" authentication scheme.

  Security considerations similar to those with `--http-password` pertain here as well.

### `--referer=url`

  Include `Referer: url' header in HTTP request.  Useful for retrieving documents with server-side processing that
  assume they are always being retrieved by interactive web browsers and only come out properly when Referer is set
  to one of the pages that point to them.

### `--save-headers`

  Save the headers sent by the HTTP server to the file, preceding the actual contents, with an empty line as the
  separator.

### `-U agent-string`, `--user-agent=agent-string`

  Identify as agent-string to the HTTP server.

  The HTTP protocol allows the clients to identify themselves using a "User-Agent" header field.  This enables
  distinguishing the WWW software, usually for statistical purposes or for tracing of protocol violations.  Wget
  normally identifies as Wget/version, version being the current version number of Wget.

  However, some sites have been known to impose the policy of tailoring the output according to the
  "User-Agent"-supplied information.  While this is not such a bad idea in theory, it has been abused by servers
  denying information to clients other than (historically) Netscape or, more frequently, Microsoft Internet
  Explorer.  This option allows you to change the "User-Agent" line issued by Wget.  Use of this option is
  discouraged, unless you really know what you are doing.

  Specifying empty user agent with `--user-agent=""` instructs Wget2 not to send the "User-Agent" header in HTTP
  requests.

### `--post-data=string`, `--post-file=file`

  Use POST as the method for all HTTP requests and send the specified data in the request body.  --post-data sends
  string as data, whereas `--post-file` sends the contents of file.  Other than that, they work in exactly the same
  way. In particular, they both expect content of the form "key1=value1&key2=value2", with percent-encoding for
  special characters; the only difference is that one expects its content as a command-line parameter and the other
  accepts its content from a file. In particular, `--post-file` is not for transmitting files as form attachments:
  those must appear as "key=value" data (with appropriate percent-coding) just like everything else. Wget2 does not
  currently support "multipart/form-data" for transmitting POST data; only "application/x-www-form-urlencoded".
  Only one of `--post-data` and `--post-file` should be specified.

  Please note that wget2 does not require the content to be of the form "key1=value1&key2=value2", and neither does
  it test for it. Wget2 will simply transmit whatever data is provided to it. Most servers however expect the POST
  data to be in the above format when processing HTML Forms.

  When sending a POST request using the `--post-file` option, Wget2 treats the file as a binary file and will send
  every character in the POST request without stripping trailing newline or formfeed characters. Any other control
  characters in the text will also be sent as-is in the POST request.

  Please be aware that Wget2 needs to know the size of the POST data in advance.  Therefore the argument to
  `--post-file` must be a regular file; specifying a FIFO or something like /dev/stdin won't work.  It's not quite
  clear how to work around this limitation inherent in HTTP/1.0.  Although HTTP/1.1 introduces chunked transfer
  that doesn't require knowing the request length in advance, a client can't use chunked unless it knows it's
  talking to an HTTP/1.1 server.  And it can't know that until it receives a response, which in turn requires the
  request to have been completed -- a chicken-and-egg problem.

  If Wget2 is redirected after the POST request is completed, its behaviour depends on
  the response code returned by the server.  In case of a 301 Moved Permanently, 302 Moved Temporarily or 307
  Temporary Redirect, Wget2 will, in accordance with RFC2616, continue to send a POST request.  In case a server
  wants the client to change the Request method upon redirection, it should send a 303 See Other response code.

  This example shows how to log in to a server using POST and then proceed to download the desired pages,
  presumably only accessible to authorized users:

      # Log in to the server.  This can be done only once.
      wget2 --save-cookies cookies.txt \
           --post-data  'user=foo&password=bar' \
           http://example.com/auth.php

      # Now grab the page or pages we care about.
      wget2 --load-cookies cookies.txt \
           -p http://example.com/interesting/article.php

  If the server is using session cookies to track user authentication, the above will not work because
  `--save-cookies` will not save them (and neither will browsers) and the cookies.txt file will be empty.  In that
  case use `--keep-session-cookies` along with `--save-cookies` to force saving of session cookies.

### `--method=HTTP-Method`

  For the purpose of RESTful scripting, Wget2 allows sending of other HTTP Methods without the need to explicitly
  set them using `--header=Header-Line`.  Wget2 will use whatever string is passed to it after `--method` as the HTTP
  Method to the server.

### `--body-data=Data-String`, `--body-file=Data-File`

  Must be set when additional data needs to be sent to the server along with the Method specified using `--method`.
  `--body-data` sends string as data, whereas `--body-file` sends the contents of file.  Other than that, they work in
  exactly the same way.

  Currently, `--body-file` is not for transmitting files as a whole.  Wget2 does not currently support
  "multipart/form-data" for transmitting data; only "application/x-www-form-urlencoded". In the future, this may be
  changed so that wget2 sends the `--body-file` as a complete file instead of sending its contents to the server.
  Please be aware that Wget2 needs to know the contents of BODY Data in advance, and hence the argument to
  `--body-file` should be a regular file. See `--post-file` for a more detailed explanation.  Only one of `--body-data`
  and `--body-file` should be specified.

  If Wget2 is redirected after the request is completed, Wget2 will suspend the current method and send a GET request
  till the redirection is completed.  This is true for all redirection response codes except 307 Temporary Redirect
  which is used to explicitly specify that the request method should not change.  Another exception is when the
  method is set to "POST", in which case the redirection rules specified under `--post-data` are followed.

### `--content-disposition`

  If this is set to on, experimental (not fully-functional) support for "Content-Disposition" headers is enabled.
  This can currently result in extra round-trips to the server for a "HEAD" request, and is known to suffer from a
  few bugs, which is why it is not currently enabled by default.

  This option is useful for some file-downloading CGI programs that use "Content-Disposition" headers to describe
  what the name of a downloaded file should be.

### `--content-on-error`

  If this is set to on, wget2 will not skip the content when the server responds with a http status code that
  indicates error.

### `--save-content-on`

  This takes a comma-separated list of HTTP status codes to save the content for.

  You can use '*' for ANY. An exclamation mark (!) in front of a code means 'exception'.

  Example 1: `--save-content-on="*,!404"` would save the content on any HTTP status, except for 404.

  Example 2: `--save-content-on=404` would save the content only on HTTP status 404.

  The older `--content-on-error` behaves like `--save-content-on=*`.

### `--trust-server-names`

  If this is set to on, on a redirect the last component of the redirection URL will be used as the local file
  name.  By default it is used the last component in the original URL.

### `--auth-no-challenge`

  If this option is given, Wget2 will send Basic HTTP authentication information (plaintext username and password)
  for all requests.

  Use of this option is not recommended, and is intended only to support some few obscure servers, which never send
  HTTP authentication challenges, but accept unsolicited auth info, say, in addition to form-based authentication.

### `--compression=TYPE`

  If this TYPE(`identity`, `gzip`, `deflate`, `xz`, `lzma`, `br`, `bzip2`, `zstd`, `lzip` or any combination of it)
  is given, Wget2 will set "Accept-Encoding" header accordingly. `--no-compression` means no "Accept-Encoding" header
  at all.
  To set "Accept-Encoding" to a custom value, use `--no-compression` in combination with
  `--header="Accept-Encoding: xxx"`.

  Compatibility-Note: `none` type in Wget 1.X has the same meaning as `identity` type in Wget2.

### `--download-attr=[strippath|usepath]`

  The `download` HTML5 attribute may specify (or better: suggest) a file name for the `href` URL in `a` and `area`
  tags. This option tells Wget2 to make use of this file name when saving. The two possible values are 'strippath'
  to strip the path from the file name. This is the default.

  The value 'usepath' takes the file name as as including the directory. This is very dangerous and we can't stress
  enough not to use it on untrusted input or servers ! Only use this if you really trust the input or the server.

## <a name="HTTPS Options"/>HTTPS (SSL/TLS) Options

  To support encrypted HTTP (HTTPS) downloads, Wget2 must be compiled with an external SSL library. The current default
  is GnuTLS.  In addition, Wget2 also supports HSTS (HTTP Strict Transport Security).  If Wget2 is compiled without SSL
  support, none of these options are available.

### `--secure-protocol=protocol`

  Choose the secure protocol to be used (default: `auto`).

  Legal values are `auto`, `SSLv3`, `TLSv1`, `TLSv1_1`, `TLSv1_2`, `TLSv1_3` and `PFS`.

  If `auto` is used, the TLS library's default is used.

  Specifying `SSLv3` forces the use of the SSL3. This is useful when talking to old and buggy SSL server
  implementations that make it hard for the underlying TLS library to choose the correct protocol version.

  Specifying `PFS` enforces the use of the so-called Perfect Forward Security cipher suites. In short, PFS adds
  security by creating a one-time key for each TLS connection. It has a bit more CPU impact on client and server.
  We use known to be secure ciphers (e.g. no MD4) and the TLS protocol.

  `TLSv1` enables TLS1.0 or higher. `TLSv1_1` enables TLS1.1 or higher.
  `TLSv1_2` enables TLS1.2 or higher. `TLSv1_3` enables TLS1.3 or higher.

  Any other protocol string is directly given to the TLS library, currently GnuTLS, as a "priority" or
  "cipher" string. This is for users who know what they are doing.

### `--https-only`

  When in recursive mode, only HTTPS links are followed.

### `--no-check-certificate`

  Don't check the server certificate against the available certificate authorities.  Also don't require the URL
  host name to match the common name presented by the certificate.

  The default is to verify the server's certificate against the recognized certificate
  authorities, breaking the SSL handshake and aborting the download if the verification fails.  Although this
  provides more secure downloads, it does break interoperability with some sites that worked with previous Wget
  versions, particularly those using self-signed, expired, or otherwise invalid certificates.  This option forces
  an "insecure" mode of operation that turns the certificate verification errors into warnings and allows you to
  proceed.

  If you encounter "certificate verification" errors or ones saying that "common name doesn't match requested host
  name", you can use this option to bypass the verification and proceed with the download.  Only use this option if
  you are otherwise convinced of the site's authenticity, or if you really don't care about the validity of its
  certificate.  It is almost always a bad idea not to check the certificates when transmitting confidential or
  important data.  For self-signed/internal certificates, you should download the certificate and verify against
  that instead of forcing this insecure mode.  If you are really sure of not desiring any certificate verification,
  you can specify `--check-certificate=quiet` to tell Wget2 to not print any warning about invalid certificates,
  albeit in most cases this is the wrong thing to do.

### `--certificate=file`

  Use the client certificate stored in file.  This is needed for servers that are configured to require
  certificates from the clients that connect to them.  Normally a certificate is not required and this switch is
  optional.

### `--certificate-type=type`

  Specify the type of the client certificate.  Legal values are PEM (assumed by default) and DER, also known as
  ASN1.

### `--private-key=file`

  Read the private key from file.  This allows you to provide the private key in a file separate from the
  certificate.

### `--private-key-type=type`

  Specify the type of the private key.  Accepted values are PEM (the default) and DER.

### `--ca-certificate=file`

  Use file as the file with the bundle of certificate authorities ("CA") to verify the peers.  The certificates
  must be in PEM format.

  Without this option Wget2 looks for CA certificates at the system-specified locations, chosen at OpenSSL
  installation time.

### `--ca-directory=directory`

  Specifies directory containing CA certificates in PEM format.  Each file contains one CA certificate, and the
  file name is based on a hash value derived from the certificate.  This is achieved by processing a certificate
  directory with the "c_rehash" utility supplied with OpenSSL.  Using `--ca-directory` is more efficient than
  `--ca-certificate` when many certificates are installed because it allows Wget2 to fetch certificates on demand.

  Without this option Wget2 looks for CA certificates at the system-specified locations, chosen at OpenSSL
  installation time.

### `--crl-file=file`

  Specifies a CRL file in file.  This is needed for certificates that have been revocated by the CAs.

### `--random-file=file`

  [OpenSSL and LibreSSL only] Use file as the source of random data for seeding the pseudo-random number generator
  on systems without /dev/urandom.

  On such systems the SSL library needs an external source of randomness to initialize.  Randomness may be provided
  by EGD (see --egd-file below) or read from an external source specified by the user.  If this option is not
  specified, Wget2 looks for random data in $RANDFILE or, if that is unset, in $HOME/.rnd.

  If you're getting the "Could not seed OpenSSL PRNG; disabling SSL."  error, you should provide random data using
  some of the methods described above.

### `--egd-file=file`

  [OpenSSL only] Use file as the EGD socket.  EGD stands for Entropy Gathering Daemon, a user-space program that
  collects data from various unpredictable system sources and makes it available to other programs that might need
  it.  Encryption software, such as the SSL library, needs sources of non-repeating randomness to seed the random
  number generator used to produce cryptographically strong keys.

  OpenSSL allows the user to specify his own source of entropy using the "RAND_FILE" environment variable.  If this
  variable is unset, or if the specified file does not produce enough randomness, OpenSSL will read random data
  from EGD socket specified using this option.

  If this option is not specified (and the equivalent startup command is not used), EGD is never contacted.  EGD is
  not needed on modern Unix systems that support /dev/urandom.

### `--hsts`

  Wget2 supports HSTS (HTTP Strict Transport Security, RFC 6797) by default.  Use `--no-hsts` to make Wget2 act as a
  non-HSTS-compliant UA. As a consequence, Wget2 would ignore all the "Strict-Transport-Security" headers, and would
  not enforce any existing HSTS policy.

### `--hsts-file=file`

  By default, Wget2 stores its HSTS data in `$XDG_DATA_HOME/wget/.wget-hsts` or, if XDG_DATA_HOME is not set, in
  `~/.local/wget/.wget-hsts`. You can use `--hsts-file` to override this.

  Wget2 will use the supplied file as the HSTS database. Such file must conform to the correct HSTS database format
  used by Wget. If Wget2 cannot parse the provided file, the behaviour is unspecified.

  To disable persistent storage use `--no-hsts-file`.

  The Wget2's HSTS database is a plain text file. Each line contains an HSTS entry (ie. a site that has issued a
  "Strict-Transport-Security" header and that therefore has specified a concrete HSTS policy to be applied). Lines
  starting with a dash ("#") are ignored by Wget. Please note that in spite of this convenient human-readability
  hand-hacking the HSTS database is generally not a good idea.

  An HSTS entry line consists of several fields separated by one or more whitespace:

      <hostname> SP [<port>] SP <include subdomains> SP <created> SP <max-age>

  The hostname and port fields indicate the hostname and port to which the given HSTS policy applies. The port
  field may be zero, and it will, in most of the cases. That means that the port number will not be taken into
  account when deciding whether such HSTS policy should be applied on a given request (only the hostname will be
  evaluated). When port is different to zero, both the target hostname and the port will be evaluated and the HSTS
  policy will only be applied if both of them match. This feature has been included for testing/development
  purposes only.  The Wget2 testsuite (in testenv/) creates HSTS databases with explicit ports with the purpose of
  ensuring Wget2's correct behaviour. Applying HSTS policies to ports other than the default ones is discouraged by
  RFC 6797 (see Appendix B "Differences between HSTS Policy and Same-Origin Policy"). Thus, this functionality
  should not be used in production environments and port will typically be zero. The last three fields do what they
  are expected to. The field include_subdomains can either be 1 or 0 and it signals whether the subdomains of the
  target domain should be part of the given HSTS policy as well. The created and max-age fields hold the timestamp
  values of when such entry was created (first seen by Wget) and the HSTS-defined value 'max-age', which states how
  long should that HSTS policy remain active, measured in seconds elapsed since the timestamp stored in created.
  Once that time has passed, that HSTS policy will no longer be valid and will eventually be removed from the
  database.

  If you supply your own HSTS database via `--hsts-file`, be aware that Wget2 may modify the provided file if any
  change occurs between the HSTS policies requested by the remote servers and those in the file. When Wget2 exits,
  it effectively updates the HSTS database by rewriting the database file with the new entries.

  If the supplied file does not exist, Wget2 will create one. This file will contain the new HSTS entries. If no
  HSTS entries were generated (no "Strict-Transport-Security" headers were sent by any of the servers) then no file
  will be created, not even an empty one. This behaviour applies to the default database file (~/.wget-hsts) as
  well: it will not be created until some server enforces an HSTS policy.

  Care is taken not to override possible changes made by other Wget2 processes at the same time over the HSTS
  database. Before dumping the updated HSTS entries on the file, Wget2 will re-read it and merge the changes.

  Using a custom HSTS database and/or modifying an existing one is discouraged.  For more information about the
  potential security threats arose from such practice, see section 14 "Security Considerations" of RFC 6797,
  specially section 14.9 "Creative Manipulation of HSTS Policy Store".

### `--hsts-preload`

  Enable loading of a HSTS Preload List as supported by libhsts. (default: on, if built with libhsts).

### `--hsts-preload-file=file`

  If built with libhsts, Wget2 uses the HSTS data provided by the distribution. If there is no such
  support by the distribution or if you want to load your own file, use this option.

  The data file must be in DAFSA format as generated by libhsts' tool `hsts-make-dafsa`.

### `--hpkp`

  Enable HTTP Public Key Pinning (HPKP) (default: on).

  This is a Trust On First Use (TOFU) mechanism to add another security layer to HTTPS (RFC 7469).

  The certificate key data of a previously established TLS session will be compared with the current
  data. In case both doesn't match, the connection will be terminated.

### `--hpkp-file=file`

  By default, Wget2 stores its HPKP data in `$XDG_DATA_HOME/wget/.wget-hpkp` or, if XDG_DATA_HOME is not set, in
  `~/.local/wget/.wget-hpkp`. You can use `--hpkp-file` to override this.

  Wget2 will use the supplied file as the HPKP database. Such file must conform to the correct HPKP database format
  used by Wget. If Wget2 cannot parse the provided file, the behaviour is unspecified.

  To disable persistent storage use `--no-hpkp-file`.

### `--tls-resume`

  Enable TLS Session Resumption which is disabled as default.

  For TLS Session Resumption the session data of a previously established TLS session is needed.

  There are several security flaws related to TLS 1.2 session resumption which are explained in detail at:
  https://web.archive.org/web/20171103231804/https://blog.filippo.io/we-need-to-talk-about-session-tickets/

### `--tls-session-file=file`

  By default, Wget2 stores its TLS Session data in `$XDG_DATA_HOME/wget/.wget-session` or, if XDG_DATA_HOME is not set, in
  `~/.local/wget/.wget-session`. You can use `--tls-session-file` to override this.

  Wget2 will use the supplied file as the TLS Session database. Such file must conform to the correct TLS Session database format
  used by Wget. If Wget2 cannot parse the provided file, the behaviour is unspecified.

  To disable persistent storage use `--no-tls-session-file`.

### `--tls-false-start`

  Enable TLS False start (default: on).

  This reduces TLS negotiation by one RT and thus speeds up HTTPS connections.

  More details at https://tools.ietf.org/html/rfc7918.

### `--check-hostname`

  Enable TLS SNI verification (default: on).

### `--ocsp`

  Enable OCSP server access to check the possible revocation the HTTPS server certificate(s) (default: off).

  This procedure is pretty slow (connect to server, HTTP request, response) and thus we support
  OSCP stapling (server sends OCSP response within TLS handshake) and persistent OCSP caching.

### `--ocsp-date`
  Check if OCSP response is too old. (default: on)

### `--ocsp-nonce`
  Allow nonce checking when verifying OCSP response. (default: on)

### `--ocsp-server`

  Set OCSP server address (default: OCSP server given in certificate).

### `--ocsp-stapling`

  Enable support for OCSP stapling (default: on).

### `--ocsp-file=file`

  By default, Wget2 stores its TLS Session data in `$XDG_DATA_HOME/wget/.wget-ocsp` or, if XDG_DATA_HOME is not set, in
  `~/.local/wget/.wget-ocsp`. You can use `--ocsp-file` to override this.

  Wget2 will use the supplied file as the OCSP database. Such file must conform to the correct OCSP database format
  used by Wget. If Wget2 cannot parse the provided file, the behaviour is unspecified.

  To disable persistent OCSP caching use `--no-ocsp-file`.

### `--dane` (experimental)
  Enable DANE certificate verification (default: off).

  In case the server verification fails due to missing CA certificates (e.g. empty certification pool),
  this option enables checking the TLSA DNS entries via DANE.

  You should have DNSSEC set up to avoid MITM attacks.
  Also, the destination host's DNS entries need to be set up for DANE.

  Warning: This option or its behavior may change or may be removed without further notice.

### `--http2`

  Enable HTTP/2 protocol (default: on).

  Wget2 requests HTTP/2 via ALPN. If available it is preferred over HTTP/1.1.
  Up to 30 streams are used in parallel within a single connection.

### `--http2-only`

  Resist on using HTTP/2 and error if a server doesn't accept it.
  This is mainly for testing.

### `--https-enforce=mode`

  Sets how to deal with URLs that are not explicitly HTTPS (where scheme isn't https://) (default: none)

#### mode=none

  Use HTTP for URLs without scheme. In recursive operation the scheme of the parent document is taken as default.

#### mode=soft

  Try HTTPS first when the scheme is HTTP or not given. On failure fall back to HTTP.

#### mode=hard

  Only use HTTPS, no matter if a HTTP scheme is given or not. Do not fall back to HTTP.

## <a name="Recursive Retrieval Options"/>Recursive Retrieval Options

### `-r`, `--recursive`

  Turn on recursive retrieving.    The default maximum depth is 5.

### `-l depth`, `--level=depth`

  Specify recursion maximum depth level depth.

### `--delete-after`

  This option tells Wget2 to delete every single file it downloads, after having done so.  It is useful for pre-
  fetching popular pages through a proxy, e.g.:

      wget2 -r -nd --delete-after https://example.com/~popular/page/

  The `-r` option is to retrieve recursively, and `-nd` to not create directories.

  Note that when --delete-after is specified, `--convert-links` is ignored, so .orig files
  are simply not created in the first place.

### `-k`, `--convert-links`

  After the download is complete, convert the links in the document to make them suitable for local viewing.  This
  affects not only the visible hyperlinks, but any part of the document that links to external content, such as
  embedded images, links to style sheets, hyperlinks to non-HTML content, etc.

  Each link will be changed in one of the two ways:

  1. The links to files that have been downloaded by Wget2 will be changed to refer to the file they point to as a
     relative link.

      Example: if the downloaded file /foo/doc.html links to /bar/img.gif, also downloaded, then the link in
      doc.html will be modified to point to ../bar/img.gif.  This kind of transformation works reliably for
      arbitrary combinations of directories.

  2. The links to files that have not been downloaded by Wget2 will be changed to include host name and absolute
     path of the location they point to.

      Example: if the downloaded file /foo/doc.html links to /bar/img.gif (or to ../bar/img.gif), then the link in
      doc.html will be modified to point to `https://example.com/bar/img.gif`.

  Because of this, local browsing works reliably: if a linked file was downloaded, the link will refer to its local
  name; if it was not downloaded, the link will refer to its full Internet address rather than presenting a broken
  link.  The fact that the former links are converted to relative links ensures that you can move the downloaded
  hierarchy to another directory.

  Note that only at the end of the download can Wget2 know which links have been downloaded.  Because of that, the
  work done by `-k` will be performed at the end of all the downloads.

### `--convert-file-only`

  This option converts only the filename part of the URLs, leaving the rest of the URLs untouched. This filename
  part is sometimes referred to as the "basename", although we avoid that term here in order not to cause
  confusion.

  It works particularly well in conjunction with `--adjust-extension`, although this coupling is not enforced. It
  proves useful to populate Internet caches with files downloaded from different hosts.

  Example: if some link points to //foo.com/bar.cgi?xyz with `--adjust-extension` asserted and its local destination
  is intended to be ./foo.com/bar.cgi?xyz.css, then the link would be converted to //foo.com/bar.cgi?xyz.css. Note
  that only the filename part has been modified. The rest of the URL has been left untouched, including the net
  path ("//") which would otherwise be processed by Wget2 and converted to the effective scheme (ie. "https://").

### `-K`, `--backup-converted`

  When converting a file, back up the original version with a .orig suffix.  Affects the behavior of `-N`.

### `-m`, `--mirror`

  Turn on options suitable for mirroring.  This option turns on recursion and time-stamping, sets infinite
  recursion depth.  It is currently equivalent to `-r -N -l inf`.

### `-p`, `--page-requisites`

  This option causes Wget2 to download all the files that are necessary to properly display a given HTML page.  This
  includes such things as inlined images, sounds, and referenced stylesheets.

  Ordinarily, when downloading a single HTML page, any requisite documents that may be needed to display it
  properly are not downloaded.  Using `-r` together with `-l` can help, but since Wget2 does not ordinarily distinguish
  between external and inlined documents, one is generally left with "leaf documents" that are missing their
  requisites.

  For instance, say document `1.html` contains an `<IMG>` tag referencing `1.gif` and an `<A>` tag pointing to external
  document `2.html`.  Say that `2.html` is similar but that its image is `2.gif` and it links to `3.html`.  Say this
  continues up to some arbitrarily high number.

  If one executes the command:

      wget2 -r -l 2 https://<site>/1.html

  then 1.html, 1.gif, 2.html, 2.gif, and 3.html will be downloaded.  As you can see, 3.html is without its
  requisite 3.gif because Wget2 is simply counting the number of hops (up to 2) away from 1.html in order to
  determine where to stop the recursion.  However, with this command:

      wget2 -r -l 2 -p https://<site>/1.html

  all the above files and 3.html's requisite 3.gif will be downloaded.  Similarly,

      wget2 -r -l 1 -p https://<site>/1.html

  will cause 1.html, 1.gif, 2.html, and 2.gif to be downloaded.  One might think that:

      wget2 -r -l 0 -p https://<site>/1.html

  would download just 1.html and 1.gif, but unfortunately this is not the case, because `-l 0` is equivalent to `-l`
  inf, that is, infinite recursion.  To download a single HTML page (or a handful of them, all specified on the
  command-line or in a `-i` URL input file) and its (or their) requisites, simply leave off `-r` and `-l`:

      wget2 -p https://<site>/1.html

  Note that Wget2 will behave as if `-r` had been specified, but only that single page and its requisites will be
  downloaded.  Links from that page to external documents will not be followed.  Actually, to download a single
  page and all its requisites (even if they exist on separate websites), and make sure the lot displays properly
  locally, this author likes to use a few options in addition to `-p`:

      wget2 -E -H -k -K -p https://<site>/<document>

  To finish off this topic, it's worth knowing that Wget2's idea of an external document link is any URL specified
  in an `<A>` tag, an `<AREA>` tag, or a `<LINK>` tag other than `<LINK REL="stylesheet">`.

### `--strict-comments`

  Obsolete option for compatibility with Wget1.x.
  Wget2 always terminates comments at the first occurrence of `-->`, as popular browsers do.

### `--robots`

  Enable the Robots Exclusion Standard (default: on).

  For each visited domain, follow rules specified in `/robots.txt`.
  You should respect the domain owner's rules and turn this off only for very good reasons.

  Whether enabled or disabled, the `robots.txt` file is downloaded and scanned for sitemaps. These are lists of pages / files
  available for download that not necessarily are available via recursive scanning.

  This behavior can be switched off by `--no-follow-sitemaps`.

## <a name="Recursive Accept/Reject Options"/>Recursive Accept/Reject Options

### `-A acclist`, `--accept=acclist`, `-R rejlist`, `--reject=rejlist`

  Specify comma-separated lists of file name suffixes or patterns to accept or reject. Note that if any of the
  wildcard characters, `*, ?, [, ]`, appear in an element of acclist or rejlist, it will be treated as a pattern,
  rather than a suffix.  In this case, you have to enclose the pattern into quotes to prevent your shell from
  expanding it, like in `-A "*.mp3"` or `-A '*.mp3'`.

### `--accept-regex=urlregex`, `--reject-regex=urlregex`

  Specify a regular expression to accept or reject file names.

### `--regex-type=regextype`

  Specify the regular expression type. Possible types are posix or pcre.  Note that to be able to use pcre type,
  wget2 has to be compiled with libpcre support.

### `--filter-urls`

  Apply the accept and reject filters on the URL before starting a download.

### `-D domain-list`, `--domains=domain-list`

  Set domains to be followed.  domain-list is a comma-separated list of domains.  Note that it does not turn on `-H`.

### `--exclude-domains=domain-list`

  Specify the domains that are not to be followed.

### `--follow-sitemaps`

  Parsing the sitemaps from `robots.txt` and follow the links. (default: on).

  This option is on for recursive downloads whether you specify `--robots` or `-no-robots`.
  Following the URLs found in sitemaps can be switched off with `--no-follow-sitemaps`.

### `--follow-tags=list`

  Wget2 has an internal table of HTML tag / attribute pairs that it considers when looking for linked documents
  during a recursive retrieval.  If a user wants only a subset of those tags to be considered, however, he or she
  should be specify such tags in a comma-separated list with this option.

### `--ignore-tags=list`

  This is the opposite of the `--follow-tags` option.  To skip certain HTML tags when recursively looking for
  documents to download, specify them in a comma-separated list.

  In the past, this option was the best bet for downloading a single page and its requisites, using a command-line
  like:

      wget2 --ignore-tags=a,area -H -k -K -r https://<site>/<document>

  However, the author of this option came across a page with tags like "<LINK REL="home" HREF="/">" and came to the
  realization that specifying tags to ignore was not enough.  One can't just tell Wget2 to ignore "<LINK>", because
  then stylesheets will not be downloaded.  Now the best bet for downloading a single page and its requisites is
  the dedicated `--page-requisites` option.

### `--ignore-case`

  Ignore case when matching files and directories.  This influences the behavior of `-R`, `-A`, `-I`, and `-X` options.
  For example, with this option, `-A` "*.txt" will match file1.txt, but also file2.TXT, file3.TxT, and so on.
  The quotes in the example are to prevent the shell from expanding the pattern.

### `-H`, `--span-hosts`

  Enable spanning across hosts when doing recursive retrieving.

### `-L`, `--relative` [Not implemented yet]

  Follow relative links only.  Useful for retrieving a specific home page without any distractions, not even those
  from the same hosts.

### `-I list`, `--include-directories=list`

  Specify a comma-separated list of directories you wish to follow when downloading.  Elements of the list may contain
  wildcards.

      wget2 -r https://webpage.domain --include-directories=*/pub/*/

  Please keep in mind that `*/pub/*/` is the same as `/*/pub/*/` and that it matches directories, not strings. This means
  that `*/pub` doesn't affect files contained at e.g. `/directory/something/pub` but `/pub/*` matches every subdir of `/pub`.

### `-X list`, `--exclude-directories=list`

  Specify a comma-separated list of directories you wish to exclude from download.  Elements of the list may contain
  wildcards.

      wget2 -r https://gnu.org --exclude-directories=/software

#### `-I` / `-X` combinations

  Please be aware that the behavior of this combination of flags works slightly different than in wget1.x.

  If `-I` is given first, the default is 'exclude all'. If `-X` is given first, the default is 'include all'.

  Multiple `-I`/`-X` options are processed 'first to last'. The last match is relevant.

      Example: `-I /pub -X /pub/trash` would download all from /pub/ except from /pub/trash.
      Example: `-X /pub -I /pub/important` would download all except from /pub where only /pub/important would be downloaded.

  To reset the list (e.g. to ignore `-I`/`-X` from `.wget2rc` files) use `--no-include-directories` or `--no-exclude-directories`.

### `-np`, `--no-parent`

  Do not ever ascend to the parent directory when retrieving recursively.  This is a useful option, since it
  guarantees that only the files below a certain hierarchy will be downloaded.

### `--filter-mime-type=list`

  Specify a comma-separated list of MIME types that will be downloaded.  Elements of list may contain wildcards.
  If a MIME type starts with the character '!' it won't be downloaded, this is useful when trying to download
  something with exceptions. If server doesn't specify the MIME type of a file it will be considered as
  'application/octet-stream'. For example, download everything except images:

      wget2 -r https://<site>/<document> --filter-mime-type=*,\!image/*

  It is also useful to download files that are compatible with an application of your system. For instance,
  download every file that is compatible with LibreOffice Writer from a website using the recursive mode:

      wget2 -r https://<site>/<document> --filter-mime-type=$(sed -r '/^MimeType=/!d;s/^MimeType=//;s/;/,/g' /usr/share/applications/libreoffice-writer.desktop)

## <a name="Plugin Options"/>Plugin Options

### `--list-plugins`

  Print a list all available plugins and exit.

### `--local-plugin=file`

  Load `file` as plugin.

### `--plugin=name`

  Load a plugin with a given `name` from the configured plugin directories.

### `--plugin-dirs=directories`

  Set plugin directories. `directories` is a comma-separated list of directories.

### `--plugin-help`

  Print the help messages from all loaded plugins.

### `--plugin-opt=option`

  Set a plugin specific command line option.

  `option` is in the format `<plugin_name>.<option>[=value]`.

# <a name="Environment"/>Environment

  Wget2 supports proxies for both HTTP and HTTPS retrievals.  The standard way to specify proxy location, which Wget
  recognizes, is using the following environment variables:

  `http_proxy`

  `https_proxy`

  If set, the `http_proxy` and `https_proxy` variables should contain the URLs of the proxies for HTTP and HTTPS
  connections respectively.

  `no_proxy`

  This variable should contain a comma-separated list of domain extensions `proxy` should not be used for.  For
  instance, if the value of `no_proxy` is `.example.com`, `proxy` will not be used to retrieve documents
  from `*.example.com`.

# <a name="Exit Status"/>Exit Status
  Wget2 may return one of several error codes if it encounters problems.

      0   No problems occurred.

      1   Generic error code.

      2   Parse error. For instance, when parsing command-line options, the .wget2rc or .netrc...

      3   File I/O error.

      4   Network failure.

      5   SSL verification failure.

      6   Username/password authentication failure.

      7   Protocol errors.

      8   Server issued an error response.

      9   Public key missing from keyring.

      10  A Signature verification failed.

  With the exceptions of 0 and 1, the lower-numbered exit codes take precedence over higher-numbered ones, when
  multiple types of errors are encountered.


# <a name="Startup File"/>Startup File

Sometimes you may wish to permanently change the default behaviour of GNU Wget2.
There is a better way to do this than setting an alias in your shell. GNU Wget2
allows you to set all options permanently through its startup up, `.wget2rc`.

While `.wget2rc` is the _main_ initialization file used by GNU Wget2, it is
not a good idea to store passwords in this file. This is because the startup
file maybe publicly readable or backed up in version control. This is why
Wget2 also reads the contents of `$HOME/.netrc` when required.

The `.wget2rc` file follows a very similar syntax to the `.wgetrc` that is read
by GNU Wget. It varies in only those places where the command line options vary
between Wget1.x and Wget2.

## <a name="Wget2rc Location"/>Wget2rc Location

When initializing, Wget2 will attempt to read the "global" startup file, which
is located at '/usr/local/etc/wget2rc' by default (or some prefix other than
'/usr/local', if Wget2 was not installed there). The global startup file is
useful for system administrators to enforce a default policy, such as setting
the path to the certificate store, preloading a HSTS list, etc.

Then, Wget2 will look for the user's initialization file. If the user has
passed the `--config` command line option, Wget2 will try to load the file that
it points to. If file does not exist, or if it cannot be read, Wget2 will
make no further attempts to read any initialization files.

If the environment variable `WGET2RC` is set, Wget2 will try to load the file
at this location. If the file does not exist, or if it cannot be read, Wget2
will make no further attempts to read an initialization file.

If, `--config` is not passed and `WGET2RC` is not set, Wget2 will attempt to
load the user's initialization file from a location as defined by the XDG Base
Directory Specification. It will read the first, and only the first file it
finds from the following locations:

1. `$XDG_CONFIG_HOME/wget/wget2rc`
2. `$HOME/.config/wget/wget2rc`
3. `$HOME/.wget2rc`

Having an initialization file at `$HOME/.wget2rc` is deprecated. If a file is
found there, Wget2 will print a warning about it. Support for reading from this
file will be removed in the future.

The fact that the user's settings are loaded after the system-wide ones means
that in case of a collision, the user's wget2rc _overrides_ the global wget2rc.

# <a name="Bugs"/>Bugs

  You are welcome to submit bug reports via the [GNU Wget2 bug tracker](https://gitlab.com/gnuwget/wget2/issues).

  Before actually submitting a bug report, please try to follow a few simple guidelines.

  1.  Please try to ascertain that the behavior you see really is a bug.  If Wget2 crashes, it's a bug.  If Wget2 does
  not behave as documented, it's a bug.  If things work strange, but you are not sure about the way they are
  supposed to work, it might well be a bug, but you might want to double-check the documentation and the mailing
  lists.

  2.  Try to repeat the bug in as simple circumstances as possible.  E.g. if Wget2 crashes while downloading `wget2 -rl0
  -kKE -t5 --no-proxy https://example.com -o /tmp/log`, you should try to see if the crash is repeatable, and if
  will occur with a simpler set of options.  You might even try to start the download at the page where the crash
  occurred to see if that page somehow triggered the crash.

  Also, while I will probably be interested to know the contents of your `.wget2rc` file, just dumping it into the
  debug message is probably a bad idea.  Instead, you should first try to see if the bug repeats with `.wget2rc` moved
  out of the way.  Only if it turns out that `.wget2rc` settings affect the bug, mail me the relevant parts of the
  file.

  3.  Please start Wget2 with `-d` option and send us the resulting output (or relevant parts thereof).  If Wget2 was
  compiled without debug support, recompile it. It is much easier to trace bugs with debug support on.

  Note: please make sure to remove any potentially sensitive information from the debug log before sending it to
  the bug address.  The `-d` won't go out of its way to collect sensitive information, but the log will contain a
  fairly complete transcript of Wget2's communication with the server, which may include passwords and pieces of
  downloaded data.  Since the bug address is publicly archived, you may assume that all bug reports are visible
  to the public.

  4.  If Wget2 has crashed, try to run it in a debugger, e.g. ```gdb `which wget` core``` and type "where" to get the
  backtrace.  This may not work if the system administrator has disabled core files, but it is safe to try.


# <a name="Author"/>Author

  Wget2 written by Tim Rühsen <tim.ruehsen@gmx.de>

  Wget 1.x originally written by Hrvoje Nikšić <hniksic@xemacs.org><br>

# <a name="Copyright"/>Copyright

  Copyright (C) 2012-2015 Tim Rühsen

  Copyright (C) 2015-2024 Free Software Foundation, Inc.

  Permission is granted to copy, distribute and/or modify this document under the terms of the GNU Free Documentation
  License, Version 1.3 or any later version published by the Free Software Foundation; with no Invariant Sections, with
  no Front-Cover Texts, and with no Back-Cover Texts.  A copy of the license is included in the section entitled "GNU
  Free Documentation License".
