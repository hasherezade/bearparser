#!/bin/bash
echo "Trying to autobuild bearparser..."

#QT check
QT_VER=`qmake -v`
QTV="version"
if echo "$QT_VER" | grep -q "$QTV"; then
    QT_FOUND=`whereis qt5`
    if echo "$QT_FOUND" | grep -q "lib"; then
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

BUILD_DIR=build

mkdir $BUILD_DIR
echo "[+] build directory created"
cd $BUILD_DIR
cmake -G "CodeLite - Unix Makefiles" -DUSE_QT4=OFF -DCMAKE_INSTALL_PREFIX:PATH=$(pwd) ..
cmake --build . --target install

