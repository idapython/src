#!/usr/bin/env bash

set -e

#ensure out folder exists
mkdir -p $3

IN_FOLDER=$(realpath $2)
OUT_FOLDER=$(realpath $3)

ARTIFACTS=$1

echo "[${ARTIFACTS}] GOING to COPY FILES from ${IN_FOLDER} to ${OUT_FOLDER}"

cd ${OUT_FOLDER}

echo "[${ARTIFACTS}] make the out folder p4 edit"
p4 edit ...

echo "[${ARTIFACTS}] copy new files"
rm -rf *
cp -R ${IN_FOLDER}/*  .

echo "[${ARTIFACTS}] adding files to p4" 
p4 add ...
p4 revert -a ...

