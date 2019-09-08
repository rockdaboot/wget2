#!/usr/bin/env bash

# Copyright (c) 2018-2019 Free Software Foundation, Inc.
#
# This file is part of GNU Wget.
#
# Wget is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Wget is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Wget.  If not, see <https://www.gnu.org/licenses/>.

# This is the Benchmarking harness. This script is the single entry point for
# performing any of the benchmarks provided here. In order to run the
# benchmarks, execute this script with the name of the benchmark to run.
#
# USAGE:
#
# $ ./benchmark [OPTIONS] -n <TEST-NAME>
#
#   Options:
#     -s		Skip downloading / updating the sources for each program
#     -b		Skip trying to rebuild each program
#     -n		The name of the test to execute
#
# The specification for each program used in the comparative Benchmarks is
# defined in the `sources/' directory, with the filename: <program>.bench.sh.
# Each of these files should define the following:
#
#	- <PROGRAMNAME>_SOURCE=https://path/to/git/repo
#	- <PROGRAMNAME>_OPTIONS="--default-options --for-all-benchmarks"
#	- <PROGRAMNAME>_BIN="./relative/path/to/binary/from/source/dir"
#	- <PROGRAMNAME>_BUILD(): Function that defines how to build a fresh copy of
#	the source
#	- <PROGRAMNAME>_VERSION(): Function to retrieve the version of the built
#	source
#
#	Do take a look at the files for Wget2 or Wget for an idea of how this is
#	done.
#
#
# Similar to the program specification, is the specification for the Benchmarks
# themselves. Each of the benchmarks is located in the 'benches/' directory.
# The benchmark specification should define the following:
#
#  - BENCHMARK_PROGRAMS as an array of programs to be used
#  - run_bench() function to execute the benchmark. It accepts 1 argument, the
#  program name.
#  - finish_bench() to finish the benchmark and cleanup. No arguments.
#
# The benchmark specification file may assume that all the variables defined in
# the program specification are available in its namespace during execution:
#
# - An empty associative array called "test_OPTIONS". Which can be filled up
# with command line options specific to this benchmark
# - KERNEL: A variable which contains the information about the currently
# running kernel. (uname -srmo)
# - PROC: A variable with information about the processor
# - PING: A variable containing the ping latency to example.com
#
# Author: Darshit Shah <darnir@gnu.org>


set -e
set -o pipefail
set -u

# Early exit if we are running in a Bash shell older than v4.
# This script relies on Bashisms which were introduced only in v4.
if ((BASH_VERSINFO[0] < 4)); then
	echo "Sorry, you need at least Bash v4 to run this script"
	exit 1
fi

# Get the location of where the script exists on disk
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly SOURCES_DIR="sources"
readonly BENCHES_DIR="benches"

# Declare arrays which are used within the sourced benchmark scripts
declare -A VERSIONS
declare -A test_OPTIONS

system_status() {
	# Global parameters defining state of test rig
	echo -e "Please wait, testing network connection ...\\n"
	readonly KERNEL="$(uname -srmo | sed 's/_/\\\\_/g')"
	readonly PROC="$(grep "model name" /proc/cpuinfo | uniq | cut -d':' -f2- | sed 's/\@/\\\\\@/g')"
	readonly PING="RTT $(ping -c 5 example.com | tail -1 | awk '{print $4}' | cut -d'/' -f2)ms to example.com"
}

# Declare pushd and popd functions to not be so verbose
pushd() {
	command pushd "$@" &> /dev/null
}

popd() {
	command popd &> /dev/null
}

# get_source <program-name>
#
# Clone the program repository or update an existing repository
get_source() {
	local program="$1"
	local PROG="${1^^}"
	if [[ ! -d "$prog" ]]; then
		local SRC_URL="${PROG}_SOURCE"
		git clone "${!SRC_URL}" "$program"
	else
		pushd "$program"
		git reset --hard HEAD
		git checkout master
		git pull origin master
		popd
	fi
}

# build_source <program-name>
#
# Call the <PROGRAM-NAME>_BUILD() function which is defined in the program
# specification to compile the program. Any configure options or CFLAGS should
# be added to the program specification file. CFLAGS may optionally be exported
# before the invocation of this script.
build_source() {
	local program="$1"
	local PROG="${1^^}"

	local BUILD_CMD="${PROG}_BUILD"
	${BUILD_CMD}
}

# Make sure we are in the directory where the script is located.
# From this point onwards, the script may make use of relative paths
cd "$SCRIPT_DIR"

# Global params that are set by the argparse code
NOSOURCE=false
NOBUILD=false

while getopts ":sb" opt; do
	case $opt in
		s) NOSOURCE=true;;
		b) NOBUILD=true;;
		:) echo "Missing argument for -$OPTARG" && exit 1;;
		\?) echo "Unknown option: $OPTARG" && exit 1;;
	esac
done

# Shift all the parsed options out. The next argument should be the name of the
# benchmark to execute
shift $((OPTIND-1))
readonly BENCH_NAME="${1:-}"

# Ensure that a valid benchmark is always available
if [[ -z $BENCH_NAME ]]; then
	echo "No benchmark specified. Exiting..."
	exit 1
elif [[ ! -f "${BENCHES_DIR}/${BENCH_NAME}.sh" ]]; then
	echo "Benchmark specification file ${BENCHES_DIR}/${BENCH_NAME}.sh not found"
	exit 1
else
	# shellcheck source=./benches/http2.sh
	source "./${BENCHES_DIR}/${BENCH_NAME}.sh"

fi

for prog in "${BENCHMARK_PROGRAMS[@]}"; do
	if [[ ! -f "${SOURCES_DIR}/${prog}.bench.sh" ]]; then
		echo "The benchmark config file for $prog not found. Exiting"
		exit 1
	fi
done

mkdir -p "$SOURCES_DIR"

system_status

echo -e "Kernel: $KERNEL\\nProcessor: $PROC\\nPing: $PING\\n"

for prog in "${BENCHMARK_PROGRAMS[@]}"; do
	echo "Running for: $prog"
	# shellcheck source=./sources/wget2.bench.sh
	source "./${SOURCES_DIR}/$prog.bench.sh"
	pushd "$SOURCES_DIR"

	if [[ $NOSOURCE == false ]]; then
		get_source "$prog"
	fi

	pushd "$prog"

	if [[ $NOBUILD == false ]]; then
		build_source "$prog" popd
	fi

	VERSION_CMD="${prog^^}_VERSION"
	VERSIONS[$prog]=$(${VERSION_CMD})
	echo "Version: ${VERSIONS[$prog]}"

	run_bench "$prog"
	popd
	popd
done
finish_bench
