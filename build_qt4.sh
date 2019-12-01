#!/bin/bash
echo "Trying to autobuild bearparser..."

#QT check
QT_VER=`qmake -v`
QTV="version"
if echo "$QT_VER" | grep -q "$QTV"; then
    QT_FOUND=`whereis qt4`
    if echo "$QT_FOUND" | grep -q "lib"; then
        echo "[+] Qt4 found!"
    else
        echo "Install Qt4 SDK first"
        exit -2
    fi
else
    echo "Install Qt4 SDK first"
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

BUILD_DIR=build_qt4

mkdir $BUILD_DIR
echo "[+] build directory created"
cd $BUILD_DIR
cmake -G "CodeLite - Unix Makefiles" -DUSE_QT4=ON -DCMAKE_INSTALL_PREFIX:PATH=$(pwd) ..
cmake --build . --target install

