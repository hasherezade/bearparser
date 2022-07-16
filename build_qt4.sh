#!/bin/bash
echo "Trying to autobuild bearparser..."

#QT check

QT_VER=`qmake -v`
str=$QT_VER
substr="Qt version 4"

echo $QT_VER
if [[ $str == *"$substr"* ]]; then
    echo "[+] Qt4 found!"
else
    str2=`whereis qt4`
    substr2="lib"
    if [[ $str2 == *"$substr2"* ]]; then
        echo "[+] Qt4 found!"
    else
        echo "Install Qt4 SDK first"
        exit -1
    fi
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

