#!/bin/bash
START_DIR=$(pwd)
SOURCE_DIR=$1
cd "$SOURCE_DIR"
echo "Source Dir: ""$SOURCE_DIR"

rm -rf test_cases
mkdir test_cases
cd test_cases
wget "https://drive.google.com/uc?export=download&id=1johP6rf7iS8-mi6xrT5mCX4wnbKk8rq8" -O test_cases.zip
unzip test_cases.zip
rm *.zip
cd ..
BCMD_DIR=$(pwd)/build/

cd test_cases
chmod +x test1.sh
./test1.sh "$BCMD_DIR" "info" "x64/QtGui4"
if [[ "$?" != 0 ]]; then
	exit 1
fi
./test1.sh "$BCMD_DIR" "winfo0" "x64/QtGui4"
if [[ "$?" != 0 ]]; then
	exit 1
fi
echo "All passed"
cd "$START_DIR"
