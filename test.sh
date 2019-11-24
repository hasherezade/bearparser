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
TEST_CASES_PATH=$(pwd)/test_cases/

cd $TESTS_DIR
chmod +x test1.sh
./test1.sh "$BCMD_DIR" "info" $TEST_CASES_PATH/"x64/QtGui4"
if [[ "$?" != 0 ]]; then
	exit 1
fi
./test1.sh "$BCMD_DIR" "winfo0" $TEST_CASES_PATH/"x64/QtGui4"
if [[ "$?" != 0 ]]; then
	exit 1
fi
echo "All passed"
cd "$START_DIR"

