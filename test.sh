#!/bin/bash
START_DIR=$(pwd)
SOURCE_DIR=$1
TESTS_DIR="test_cases"

echo "Source Dir: ""$SOURCE_DIR"
cd "$SOURCE_DIR"

if [ -d $TESTS_DIR ]; then
	echo "Test directory already exits"
else
	git clone https://github.com/hasherezade/bearparser_tests.git
	mv bearparser_tests $TESTS_DIR
fi

BCMD_DIR=$(pwd)/build/
FAILED=0

cd $TESTS_DIR
chmod +x test1.sh
./test1.sh "$BCMD_DIR" "info" "x64/QtGui4"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi
./test1.sh "$BCMD_DIR" "winfo0" "x64/QtGui4"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi
./test1.sh "$BCMD_DIR" "winfo1" "x64/QtGui4"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi
./test1.sh "$BCMD_DIR" "secinfo" "x64/QtGui4"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi
#./test1.sh "$BCMD_DIR" "secinfo" "x86/overlapping_sec"
#if [[ "$?" != 0 ]]; then
#	FAILED=$FAILED+1
#fi

./test1.sh "$BCMD_DIR" "info" "tinype/tiny.128/tiny"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi
./test1.sh "$BCMD_DIR" "winfo3" "tinype/tiny.128/tiny"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi

./test1.sh "$BCMD_DIR" "winfo7" "x86/ghost_crackme"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi

./test1.sh "$BCMD_DIR" "rstrings" "x86/ghost_crackme"
if [[ "$?" != 0 ]]; then
	FAILED=$FAILED+1
fi


if [[ "$FAILED" == 0 ]]; then
	echo "All passed"
fi

cd "$START_DIR"

