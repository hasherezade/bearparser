#pragma once

#include "Executable.h"

class ExeFactoryException : public CustomException
{
public:
    ExeFactoryException(const QString info) : CustomException(info) {}
};

class ExeFactory
{
public:
    enum exe_type {
        NONE = 0,
        PE = 1,
        MZ,
        TYPES_COUNT
    };

    static void init();
    static void destroy();

    static exe_type findMatching(AbstractByteBuffer *buf);
    static Executable* build(AbstractByteBuffer *buf, exe_type type);
    static QString getTypeName(exe_type type);

protected:
    static std::map<exe_type, ExeBuilder*> builders;
};
