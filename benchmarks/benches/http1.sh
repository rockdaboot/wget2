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

readonly BENCHMARK_PROGRAMS=("wget" "wget2" "curl")
readonly BENCHM_NAME="http1"
test_OPTIONS["WGET"]=""
test_OPTIONS["WGET2"]="--no-http2"
test_OPTIONS["CURL"]="--http1.1"

readonly NITER=10
readonly NURL=5

time_cmd() {
	local cmd="$1"
	local nurls="$2"
	local data_file="$3"
	echo "$cmd"
	for ((i=0;i<NITER;i++)); do
		t1=$(date +%s%3N)
		$cmd &>/dev/null
		t2=$(date +%s%3N)
		echo "$nurls" $((t2-t1))
		echo -n "." >&2
		sleep 1s
	done >> "$data_file"
	echo ""
}

run_bench() {
	local program="$1"
	local PROG="${1^^}"
	local binary="${PROG}_BIN"
	local prog_options="${PROG}_OPTIONS"
	local prog_test_options="${test_OPTIONS[$PROG]}"
	local cmdline="${!binary} ${!prog_options:-} ${prog_test_options} https://www.example.com/?test=1"

	rm -f "../../${program}_${BENCHM_NAME}.data"

	# Warmup Run
	$cmdline

	for ((nreq=1; nreq<=NURL; nreq++)); do
		local urls=""
		for ((i=1; i<=nreq; i++)); do
			urls="$urls https://www.example.com/?test=$i"
		done

		time_cmd "${!binary} ${!prog_options} ${prog_test_options:-} $urls" $nreq "../../${program}_${BENCHM_NAME}.data"

	done
}

finish_bench() {
	local plot_title=""
	local plot_cmd
	local plot_title_left

	pushd "$SCRIPT_DIR"

	plot_title_left="HTTPS with HTTP/1.1\\n\
		$KERNEL\\n\
		$PROC\\n\
		ping $PING"
	plot_cmd="plot"
	local colornum=1
	for prog in "${BENCHMARK_PROGRAMS[@]}"; do
		gnuplot -c "${BENCHES_DIR}/convert.gp" "${prog}_${BENCHM_NAME}.data" "$NURL"
		local prog_options="${prog^^}_OPTIONS"
		local prog_test_options="${test_OPTIONS[${prog^^}]}"
		plot_title="$plot_title\\n\
			$prog ${VERSIONS[$prog]} ${!prog_options} ${prog_test_options:-}"
		if [[ $plot_cmd == "plot" ]]; then
			plot_cmd="${plot_cmd} \"processed_${prog}_${BENCHM_NAME}.data\" using 1:2 with linespoints title \"$prog\" lt $colornum"
		else
			plot_cmd="${plot_cmd}, \"processed_${prog}_${BENCHM_NAME}.data\" using 1:2 with linespoints title \"$prog\" lt $colornum"
		fi
		plot_cmd="${plot_cmd}, \"processed_${prog}_${BENCHM_NAME}.data\" using 1:2:3:4 with yerrorbars notitle lt $colornum"
		((colornum=colornum+1))
	done
	cat <<EOF | gnuplot
	set terminal svg
	set output "http1.svg"

	set label 1 "$plot_title_left"
	set label 2 "$plot_title"
	set label 1 at character 3, 25
	set label 2 at character 37, 26

	# aspect ratio, for image size
	set size 1,0.8

	set grid y
	set xtics 1
	set xlabel "number of URLs"
	set ylabel "wall time (ms)"

	$plot_cmd
EOF
	popd
}
