#include "WrappedValue.h"

QVariant WrappedValue::getQVariant()
{
    if (m_Type == INT) {
        bool isOk = false;

        qlonglong num = (qlonglong) m_Owner->getNumValue(m_Offset, m_Size, &isOk);
        if (!isOk) return QVariant("INVALID");
        return QVariant(num);
    }
    if (m_Type == STRING) {
        char *strPtr = (char*) this->m_Owner->getContentAt(m_Offset, m_Size);
        if (strPtr == NULL) return QVariant();
        return QString(strPtr);
    }
    if (this->m_Type == WSTRING) {

        bufsize_t wSize = m_Size / bufsize_t(sizeof(WORD));
        WORD *strPtr = (WORD*) this->m_Owner->getContentAt(m_Offset, m_Size);
        return QString::fromUtf16(strPtr, static_cast<int>(wSize));
    }
    return QVariant("...");
}

QString WrappedValue::getIntFormat()
{
    QString format = "%0" + QString::number(m_Size * 2) +"llX";
    return format;
}

QString WrappedValue::toQString()
{
    if (this->m_Type == NONE) return "";
    if (this->m_Type == COMPLEX) return "...";

    QVariant val = getQVariant();

    if (this->m_Type == STRING || this->m_Type == WSTRING) {
        return val.toString();
    }
    if (this->m_Type == INT) {

        bufsize_t size = this->m_Size;
        if (size > sizeof(uint64_t)) return  "...";

        bool isOk = false;
        uint64_t num = m_Owner->getNumValue(m_Offset, m_Size, &isOk);
        if (!isOk) return "INVALID";
        QString out;
        return out.asprintf(getIntFormat().toStdString().c_str(), num);
    }
    return getQVariant().toString();
}
