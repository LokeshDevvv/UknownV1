#!/bin/bash

# Create icons directory
mkdir -p icons

# Generate base icon with cyberpunk shield design
convert -size 128x128 xc:none \
  -fill '#0a0a0f' -draw 'rectangle 0,0 128,128' \
  -fill '#00ffff' -draw 'polygon 64,20 108,44 108,84 64,108 20,84 20,44' \
  -fill '#0a0a0f' -draw 'polygon 64,30 98,49 98,79 64,98 30,79 30,49' \
  -fill '#00ffff' -strokewidth 2 -draw 'line 64,40 64,88' \
  -draw 'line 44,54 84,54' \
  icons/icon128.png

# Create smaller versions
convert icons/icon128.png -resize 48x48 icons/icon48.png
convert icons/icon128.png -resize 16x16 icons/icon16.png 