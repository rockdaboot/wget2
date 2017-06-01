#!/bin/sh

for f in $1.in/*; do
  $1 < $f >/dev/null
done
