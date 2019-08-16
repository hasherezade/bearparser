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

mkdir build_qt4
echo "[+] build directory created"
cd build_qt4
cmake -G "CodeLite - Unix Makefiles" -D USE_QT5=OFF ../
make
cd ..
cp build/commander/bearcommander ./build_qt4/
echo "[+] Success! You can check the executable here:"
pwd
