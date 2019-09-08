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
#
# Supplementary gnuplot script to convert data formats
#
# convert.gp: Convert a given file containing multiple data points for each X
# value into a data file that represents the mean of each of those points. This
# allows us to plot a graph for the mean of the observed values along with a
# range showing a 95% Confidence Interval.

filename = ARG1
output_filename = sprintf("processed_%s", filename)
nurls = ARG2

array student_t[101] = [3.078, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, \
2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, \
2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, \
2.042, 2.021, 2.009, 2.000, 1.994, 1.990, 1.987, 1.984, 1.960]

set print output_filename

print "# THIS IS A GENERATED FILE (DO NOT EDIT)"
do for [i=1:nurls] {
	stats filename using ($1==i?$2:1/0) name "urlnum" nooutput
	# Get the critical value of the Student's T-Distribution for a 95% CI
	# The Degree of Freedom is 1 less than number of elements
	student_val = student_t[urlnum_records-1]

	print i, urlnum_mean, (urlnum_mean - student_val*urlnum_ssd / sqrt(urlnum_records)), (urlnum_mean + student_val*urlnum_ssd/sqrt(urlnum_records))
}

# vim: set ts=4 sts=4 sw=4 tw=79 ft=gnuplot noet :
