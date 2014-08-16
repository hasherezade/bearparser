#pragma once

#include "win_hdrs/win_types.h"
#include "AbstractByteBuffer.h"

class AbstractFormatter
{
public:
    AbstractFormatter(AbstractByteBuffer *v_buf);
    virtual ~AbstractFormatter() {}

    virtual const QString operator[](std::size_t idx) const = 0;

protected:
    AbstractByteBuffer *buf;
};

class Formatter : public AbstractFormatter{
public:
    Formatter(AbstractByteBuffer *buf) : AbstractFormatter(buf) {}

    const QString operator[](std::size_t idx) const;
};

class HexFormatter :public AbstractFormatter
{
public:
    HexFormatter(AbstractByteBuffer *buf) : AbstractFormatter(buf) {}

    const QString operator[](std::size_t idx) const;
};
/*
class BufferPrinter
{
public:
    enum FORMATTERS {
        F_TEXT = 0,
        F_HEX = 1,
        COUNT_FORMATTERS
    };

    BufferPrinter();
    ~BufferPrinter() { clearFormatters(); }

    bool addFormater(int formatterId, AbstractFormatter *formatter);
    bool useFormatter(int formatterId);

protected:
    void clearFormatters();

    AbstractFormatter *strategy;

    std::map<int, AbstractFormatter> formatters;
};
*/
