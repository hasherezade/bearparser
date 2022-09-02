#include "pe/FileHdrWrapper.h"
#include "pe/PEFile.h"

#include <time.h>
#include <QDateTime>

QString getDateString(const quint64 timestamp)
{
    const time_t rawtime = (const time_t)timestamp;
    QString format = "dddd, dd.MM.yyyy hh:mm:ss";
    QDateTime date1(QDateTime(QDateTime::fromTime_t(rawtime)));
    return date1.toUTC().toString(format) + " UTC";
}

void* FileHdrWrapper::getPtr()
{
    if (this->hdr) {
        // use cached if exists
        return (void*) hdr;
    }
    if (m_PE == NULL) return NULL;

    offset_t myOff = m_PE->peFileHdrOffset();
    IMAGE_FILE_HEADER* hdr = (IMAGE_FILE_HEADER*) m_Exe->getContentAt(myOff, sizeof(IMAGE_FILE_HEADER));
    if (!hdr) return NULL; //error

    return (void*) hdr;
}


void* FileHdrWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    IMAGE_FILE_HEADER * hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(getPtr());
    if (!hdr) return NULL;

    IMAGE_FILE_HEADER &fileHeader = (*hdr);
    switch (fieldId) {
         case MACHINE: return (void*) &fileHeader.Machine;
         case SEC_NUM: return (void*) &fileHeader.NumberOfSections;
         case TIMESTAMP: return (void*) &fileHeader.TimeDateStamp;
         case SYMBOL_PTR: return (void*) &fileHeader.PointerToSymbolTable;
         case SYMBOL_NUM: return (void*) &fileHeader.NumberOfSymbols;
         case OPTHDR_SIZE: return (void*) &fileHeader.SizeOfOptionalHeader;
         case CHARACT: return (void*) &fileHeader.Characteristics;
    }
    return (void*) &fileHeader;
}

QString FileHdrWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
         case MACHINE: return("Machine");
         case SEC_NUM: return ("Sections Count");
         case TIMESTAMP: return("Time Date Stamp");
         case SYMBOL_PTR: return("Ptr to Symbol Table");
         case SYMBOL_NUM: return("Num. of Symbols");
         case OPTHDR_SIZE: return("Size of OptionalHeader");
         case CHARACT: return("Characteristics");
    }
    return "";
}

Executable::addr_type FileHdrWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    return Executable::NOT_ADDR;
}

QString FileHdrWrapper::translateFieldContent(size_t fieldId)
{
    IMAGE_FILE_HEADER * hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(getPtr());
    if (!hdr) return "";

    IMAGE_FILE_HEADER &fileHeader = (*hdr);
    switch (fieldId) {
         case TIMESTAMP: return getDateString(fileHeader.TimeDateStamp);
    }
    return "";
}

