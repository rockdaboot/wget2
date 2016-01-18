#!/bin/sh

# This little script generates the current Wget logo for the HTML docs.
# Needs ImageMagick

convert -size 256x88 xc:transparent -font Palatino-Bold -pointsize 72 -draw "text 25,60 'Wget2'" -channel RGBA -gaussian 0x6 -fill black -stroke green -draw "text 20,55 'Wget2'" wget-logo.png
