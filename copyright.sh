#!/bin/sh

#shopt -s globstar nullglob extglob

for f in **/*.c; do
  cat copyright $f > $f.new
  mv $f.new $f
done

