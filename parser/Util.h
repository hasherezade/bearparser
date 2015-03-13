#pragma once

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <QtCore>
#include "win_hdrs/win_types.h"

#define DEFAULT_BUFSIZE 0xFF
#define IS_PRINTABLE(c) (c >= 0x20 && c < 0x7f)
#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)

namespace pe_util {
    inline bool isPrintable(char c) { return IS_PRINTABLE(c); }

    bool isStrLonger(const char *inp, int maxLen);
    //QString getString(const char *ptr, size_t maxInp, size_t maxBuf = DEFAULT_BUFSIZE);
    bool hasNonPrintable(const char *ptr, size_t maxInp);
    size_t getAsciiLen(const char *ptr, size_t maxCount, bool acceptNotTerminated = false);
    size_t getAsciiLenW(const WORD *ptr, size_t maxCount, bool acceptNotTerminated = false);

    size_t noWhiteCount(char *buf, size_t bufSize);
    size_t noWhiteCount(std::string);

    void hexdump(BYTE *buf, size_t bufSize, size_t pad);
    inline uint64_t roundup(uint64_t value, uint64_t unit) { return unit == 0 ? 0 : ((value + unit - 1) / unit) * unit; }

    bool isSpaceClear(void* ptr, uint64_t size);
    bool isHexChar(char c);

    bool endsWith(std::string string, std::string endStr);
};

