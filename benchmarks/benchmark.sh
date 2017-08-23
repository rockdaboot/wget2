#!/usr/bin/env bash

set -e
set -o pipefail
set -u


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WGET="$SCRIPT_DIR/../../wget/src/wget"
WGET2="$SCRIPT_DIR/../src/wget2_noinstall"
CURL="$SCRIPT_DIR/../../curl/src/curl"

WGET_OPTIONS="-q --no-config -O/dev/null"
WGET2_OPTIONS="-q --no-config -O/dev/null"
CURL_OPTIONS="-s -o/dev/null --cert-status"

WGET_http1_OPTIONS=""
WGET2_http1_OPTIONS="--no-http2"
CURL_http1_OPTIONS="--http1.1"
WGET_http2_OPTIONS=""
WGET2_http2_OPTIONS="--http2"
CURL_http2_OPTIONS="--http2"

NCHECKS=20
MINX=1
MAXX=5
SLEEP=0.5

#Prepare Values
KERNEL="$(uname -srmo | sed 's/_/\\_/g')"
PROC="$(grep "model name" /proc/cpuinfo | uniq | cut -d':' -f2-)"
PING="$(ping -c 5 example.com | tail -1 | awk '{print $4}' | cut -d'/' -f2)"
WGET_VERSION="$($WGET --version | head -1 | cut -d' ' -f3)"
WGET2_VERSION="$($WGET2 --version | head -1 | cut -d' ' -f3)"
CURL_VERSION="$($CURL --version | head -1 | cut -d' ' -f2)"

time_cmd() {
	local cmd="$1"
	local nurls="$2"
	local data_file="$3"
	echo "$cmd"
	for ((i=0;i<NCHECKS;i++)); do
		t1=$(date +%s%3N)
		$cmd &>/dev/null
		t2=$(date +%s%3N)
		echo "$nurls" $((t2-t1))
		sleep $SLEEP
	done >> "$data_file"
}

plot() {
	ttype="$1"
	title="$2"
	local wget_opt="WGET_${ttype}_OPTIONS"
	local wget2_opt="WGET2_${ttype}_OPTIONS"
	local curl_opt="CURL_${ttype}_OPTIONS"
	gtitle="$title\n\
	$KERNEL, $PROC\n\
	ping RTT $PING to example.com\n\
	wget $WGET_VERSION options: $WGET_OPTIONS ${!wget_opt}\n\
	wget2 $WGET2_VERSION options: $WGET2_OPTIONS ${!wget2_opt}\n\
	curl $CURL_VERSION options: $CURL_OPTIONS ${!curl_opt}"

	cat <<EOF | gnuplot
	set terminal svg
	set output "$1.svg"

	set title "$gtitle"

	# aspect ratio, for image size
	# set size 1,0.7

	set grid y
	set xlabel "number of URLs"
	set ylabel "wall time (ms)"

	plot \
		"wget_$ttype.data" using 1:2 smooth sbezier with lines title "Wget", \
		"wget2_$ttype.data" using 1:2 smooth sbezier with lines title "Wget2", \
		"curl_$ttype.data" using 1:2 smooth sbezier with lines title "Curl"
EOF
}

rm -f wget.data wget2.data curl.data

for ((nreq=MINX;nreq<=MAXX;nreq++)); do
	urls=""
	for ((i=1;i<=nreq;i++)); do
		urls="$urls https://www.example.com/?test=$i"
	done

	#Warmup Run
	if [ $nreq -eq 1 ]; then
		$WGET $WGET_OPTIONS $urls
		$WGET2 $WGET2_OPTIONS $urls
		$CURL $CURL_OPTIONS $urls
	fi

	time_cmd "$WGET $WGET_OPTIONS $WGET_http1_OPTIONS $urls" $nreq wget_http1.data
	time_cmd "$WGET2 $WGET2_OPTIONS $WGET2_http1_OPTIONS $urls" $nreq wget2_http1.data
	time_cmd "$CURL $CURL_OPTIONS $CURL_http1_OPTIONS $urls" $nreq curl_http1.data

	time_cmd "$WGET $WGET_OPTIONS $WGET_http2_OPTIONS $urls" $nreq wget_http2.data
	time_cmd "$WGET2 $WGET2_OPTIONS $WGET2_http2_OPTIONS $urls" $nreq wget2_http2.data
	time_cmd "$CURL $CURL_OPTIONS $CURL_http2_OPTIONS $urls" $nreq curl_http2.data
done

plot "http1" "HTTPS with HTTP/1.1"
plot "http2" "HTTPS with HTTP/2"
