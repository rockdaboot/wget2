# !/bin/sh -e

AUTORECONF=`which autoreconf 2>/dev/null`
if test $? -ne 0; then
  echo "No 'autoreconf' found. You must install the autoconf package."
  exit 1
fi

GIT=$(which git 2>/dev/null)
if test $? -ne 0; then
  echo "No 'git' found. You must install the git package."
  exit 1
fi

$GIT submodule init
$GIT submodule update

# gnulib modules needed for libwget
libwget_gnulib_modules="
accept
bind
c-strcase
c-ctype
calloc-posix
clock-time
close
closedir
connect
dup2
errno
fclose
fcntl
fdopen
fflush
flock
fnmatch
fopen
fstat
futimens
getaddrinfo
getsockname
gettext-h
gettime
glob
iconv
inline
inttypes
lib-symbol-visibility
listen
malloc-posix
memchr
mkdir
mkstemp
nanosleep
netdb
netinet_in
nl_langinfo
open
opendir
progname
spawn-pipe
popen
poll
pthread
pwrite
qsort_r
random_r
read
readdir
realloc-posix
rename
send
sendto
servent
setlocale
setsockopt
socket
stdarg
stdbool
stddef
stdint
stat
strcase
strdup-posix
strerror
strndup
strstr
strtoll
sys_file
sys_socket
sys_stat
sys_time
sys_types
time_r
unlink
write
"

gnulib/gnulib-tool --libtool --import $libwget_gnulib_modules

$AUTORECONF --install --force --symlink || exit $?

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure"
echo
