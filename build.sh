#!/bin/bash
echo "Trying to autobuild bearparser..."

#QT check
QT_VER=`qmake -v`
QTV="version"
if echo "$QT_VER" | grep -q "$QTV"; then
    QT4_FOUND=`whereis qt5`
    if echo "$QT4_FOUND" | grep -q "lib"; then
        echo "[+] Qt5 found!"
    else
        echo "Install Qt5 SDK first"
        exit -2
    fi
else
    echo "Install Qt5 SDK first"
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
