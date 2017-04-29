#!/bin/bash
#
# Generate a Markdown list of CLI option diffs of Wget/Wget2
#
# Make sure you are in the correct directory

wget/src/wget --help|grep -- ' --'|cut -c8-|awk '{print $1}'|cut -d'=' -f1|\
while read i; do if [ ${i:0:5} = '--no-' ]; then echo --${i:5}; else echo $i; fi; done |\
sort -u >wget/options.txt

wget2/src/wget2 --help|grep -- ' --'|cut -c7-|awk '{print $1}'|grep -- ^--|sort -u >wget2/options.txt

diff wget/options.txt wget2/options.txt |\
while read i; do
  if [ ${i:0:1} = '<' ]; then
    echo ${i:2}"|✓||"
  elif [ ${i:0:1} = '>' ]; then
    echo ${i:2}"||✓|"
  fi
done | sort
