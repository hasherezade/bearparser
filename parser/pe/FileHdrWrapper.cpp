#include "pe/FileHdrWrapper.h"
#include "pe/PEFile.h"

#include <time.h>
#include <QDateTime>

namespace util {
    QString getDateString(const quint64 timestamp)
    {
        const time_t rawtime = (const time_t)timestamp;
        QString format = "dddd, dd.MM.yyyy hh:mm:ss";
        QDateTime date1(QDateTime(QDateTime::fromTime_t(rawtime)));
        return date1.toUTC().toString(format) + " UTC";
    }
};


std::map<DWORD, QString> FileHdrWrapper::s_fHdrCharact;

void FileHdrWrapper::initCharact()
{
    if (s_fHdrCharact.size() != 0) {
        return; //already initialized
    }
    s_fHdrCharact[F_RELOCS_STRIPPED] = "Relocation info stripped from file.";
    s_fHdrCharact[F_EXECUTABLE_IMAGE] = "File is executable  (i.e. no unresolved externel references).";
    s_fHdrCharact[F_LINE_NUMS_STRIPPED] = "Line nunbers stripped from file.";
    s_fHdrCharact[F_LOCAL_SYMS_STRIPPED] = "Local symbols stripped from file.";
    s_fHdrCharact[F_AGGRESIVE_WS_TRIM] = "Agressively trim working set";
    s_fHdrCharact[F_LARGE_ADDRESS_AWARE] = "App can handle >2gb addresses";
    s_fHdrCharact[F_BYTES_REVERSED_LO] = "Bytes of machine word are reversed.";
    s_fHdrCharact[F_MACHINE_32BIT] = "32 bit word machine.";
    s_fHdrCharact[F_DEBUG_STRIPPED] = "Debugging info stripped from file in .DBG file";
    s_fHdrCharact[F_REMOVABLE_RUN_FROM_SWAP] = "If Image is on removable media, copy and run from the swap file.";
    s_fHdrCharact[F_NET_RUN_FROM_SWAP] = "If Image is on Net, copy and run from the swap file.";
    s_fHdrCharact[F_SYSTEM] = "System File.";
    s_fHdrCharact[F_DLL] = "File is a DLL.";
    s_fHdrCharact[F_UP_SYSTEM_ONLY] = "File should only be run on a UP machine";
    s_fHdrCharact[F_BYTES_REVERSED_HI] = "Bytes of machine word are reversed.";
}

std::vector<DWORD> FileHdrWrapper::splitCharact(DWORD characteristics)
{
    if (s_fHdrCharact.size() == 0) initCharact();

    std::vector<DWORD> chSet;
    for (std::map<DWORD, QString>::iterator iter = s_fHdrCharact.begin(); iter != s_fHdrCharact.end(); iter++) {
        if (characteristics & iter->first) {
            chSet.push_back(iter->first);
        }
    }
    return chSet;
}

QString FileHdrWrapper::translateCharacteristics(DWORD charact)
{
    if (s_fHdrCharact.size() == 0) initCharact();

    if (s_fHdrCharact.find(charact) == s_fHdrCharact.end()) return "";
    return s_fHdrCharact[charact];
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
        case TIMESTAMP: return util::getDateString(fileHeader.TimeDateStamp);
    }
    return "";
}

