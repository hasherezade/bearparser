#include "Formatter.h"
#include "Util.h"

//----------------
AbstractFormatter::AbstractFormatter(AbstractByteBuffer *v_buf)
    : buf(v_buf)
{
    if (v_buf == NULL) throw BufferException("Cannot make HexFilter for NULL buffer!");
}

//---------------------------------------------------
const QString Formatter::operator[](std::size_t idx) const
{
    BYTE b = (*buf)[idx];
    if (pe_util::isPrintable(b) == false)
        return "\\x"+ QString::number(b, 16).leftJustified(2,'0');
    return QString(b);
}

const QString HexFormatter::operator[](std::size_t idx) const
{
    BYTE b = (*buf)[idx];
    return QString::number(b, 16).leftJustified(2,'0');
}
/*

BufferPrinter::BufferPrinter()
{
    this->addFormater(int formatterId, AbstractFormatter);

}


bool BufferPrinter::addFormater(int formatterId, AbstractFormatter *formatter)
{
    if (this->formatters[formatterId] != NULL) {
        return false; //already exist
    }
    this->formatters[formatterId] = formatter;
    return true;
}

bool BufferPrinter::useFormatter(int formatterId)
{
    if (this->formatters[formatterId] == NULL) {
        return false; //no such formatter
    }
    this->strategy = this->formatters[formatterId];
    return true;
}

void BufferPrinter::clearFormatters()
{
    std::map<int, AbstractFormatter*>::iterator itr;
    for (itr = formatters.begin(); itr != formatters.end(); itr++) {
        AbstractFormatter* f = itr->second;
        delete f;
    }
    formatters.clear();
}
*/
