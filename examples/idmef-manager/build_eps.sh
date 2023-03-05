#!/bin/bash

DIA=/usr/local/bin/dia

for file in *.dia
do
  echo "processing $file..."
  test -f $file && $DIA --export=$(basename $file .dia).eps $file
done
