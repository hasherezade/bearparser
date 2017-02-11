#!/bin/bash
echo "Trying to autobuild bearparser..."

#QT check
QT_VER=`qmake -v`
QTV="version 5."
if echo "$QT_VER" | grep -q "$QTV"; then
    echo "[+] Qt5 found!"
else
    echo "[-] Qt5 NOT found!"
    echo "Install Qt5 SDK (qt5-default) first"
    exit -1
fi

CMAKE_VER=`cmake --version`
CMAKEV="cmake version"
if echo "$CMAKE_VER" | grep -q "$CMAKEV"; then
    echo "[+] CMake found!"
else
    echo "[-] CMake NOT found!"
    echo "Install cmake first"
    exit -1
fi

mkdir bearparser
cd bearparser
git clone https://github.com/hasherezade/bearparser.git
echo "[+] bearparser cloned"
echo $$
cd bearparser
git checkout qt5
cd ..
mv bearparser src
mkdir build
echo "[+] build directory created"
cd build
cmake -G "Unix Makefiles" ../src/
make
cd ..
cp build/commander/bearcommander ./
echo "[+] Success! You can check the executable here:"
pwd
