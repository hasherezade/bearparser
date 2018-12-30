#!/bin/bash
echo "Trying to autobuild bearparser..."

#QT check
QT_VER=`qmake -v`
QTV="version"
if echo "$QT_VER" | grep -q "$QTV"; then
    echo "[+] Qt found!"
else
    echo "[-] Qt NOT found!"
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

mkdir build
echo "[+] build directory created"
cd build
cmake -G "Unix Makefiles" ../
make
cd ..
cp build/commander/bearcommander ./build/
echo "[+] Success! You can check the executable here:"
pwd
