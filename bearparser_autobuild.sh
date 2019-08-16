#!/bin/bash
echo "Trying to autobuild bearparser..."

git clone https://github.com/hasherezade/bearparser.git
echo "[+] bearparser cloned"
echo $$
cd bearparser
sh build.sh

