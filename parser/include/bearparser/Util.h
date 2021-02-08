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

//----
#ifdef _DEBUG
#define DBG_LVL 2
#else
#define DBG_LVL 0
#endif

#define TRACE() if (DBG_LVL) printf(">%s line:  %d [%s]\n", __FUNCTION__, __LINE__, __FILE__);
#define LOG(msg) if (DBG_LVL) printf("%s: %s\n", __FUNCTION__,msg);

namespace Logger {
    enum dbg_level{
        D_ERROR = 0, D_WARNING, D_INFO, D_LVL_COUNT
    };
    bool append(dbg_level lvl, const char* format, ...);
};
//----
namespace pe_util {
    inline bool isPrintable(char c) { return IS_PRINTABLE(c); }

    bool isStrLonger(const char *inp, size_t maxLen);
    //QString getString(const char *ptr, size_t maxInp, size_t maxBuf = DEFAULT_BUFSIZE);
    bool hasNonPrintable(const char *ptr, size_t maxInp);
    size_t getAsciiLen(const char *ptr, size_t maxCount, bool acceptNotTerminated = false);
    size_t getAsciiLenW(const WORD *ptr, size_t maxCount, bool acceptNotTerminated = false);

    size_t noWhiteCount(char *buf, size_t bufSize);
    size_t noWhiteCount(std::string);
    size_t forwarderNameLen(const char *ptr, size_t max_len);

    void hexdump(BYTE *buf, size_t bufSize, size_t pad);
    inline uint64_t roundup(uint64_t value, uint64_t unit) { return unit == 0 ? 0 : ((value + unit - 1) / unit) * unit; }

    bool isSpaceClear(void* ptr, uint64_t size);
    bool isHexChar(char c);

    bool endsWith(std::string string, std::string endStr);
};

