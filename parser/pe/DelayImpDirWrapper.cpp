#include "DelayImpDirWrapper.h"
#include "PEFile.h"

using namespace pe;

/*
typedef struct _IMAGE_DELAY_LOAD {
    DWORD grAttrs;        //must be 0
    DWORD szName;        //RVA
    DWORD phmod;        //RVA
    DWORD pIAT;            //RVA
    DWORD pINT;            //RVA
    DWORD pBoundIAT;    //RVA
    DWORD pUnloadIAT;    //RVA
    DWORD dwTimestamp;
} IMAGE_DELAY_LOAD, *LPIMAGE_DELAY_LOAD;

*/

void* DelayImpDirWrapper::firstDelayLd(bufsize_t size)
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, size);
    if (ptr == NULL) return NULL;

    return ptr;
}

bool DelayImpDirWrapper::loadNextEntry(size_t cntr)
{
    DelayImpEntryWrapper* imp = new DelayImpEntryWrapper(m_Exe, this, cntr);
    if (!imp || !imp->getPtr()) {
        delete imp;
        return false;
    }
    // TODO! do it in proper way!
    bool isOk = false;
    uint64_t offset = imp->getNumValue(DelayImpEntryWrapper::NAME, &isOk);
    if (!isOk || offset == 0) {
        delete imp;
        return false;
    }
        //printf("Name = %s\n", imp->getName().c_str());
    entries.push_back(imp);
    return true;
}

void* DelayImpDirWrapper::getPtr()
{
    bufsize_t size = getEntrySize();
    return firstDelayLd(size);
}

bufsize_t DelayImpDirWrapper::getSize()
{
    bufsize_t entriesNum = static_cast<bufsize_t>(this->getEntriesCount()) + 1; //entries + terminating field
    return getEntrySize() * entriesNum;
}

bufsize_t DelayImpDirWrapper::getEntrySize()
{
    Executable::exe_bits bitMode = m_Exe->getBitMode();
    size_t size = 0;

    if (bitMode == Executable::BITS_64) {
        size = sizeof(pe::IMAGE_DELAY_LOAD64);
    } else if (bitMode == Executable::BITS_32) {
        size = sizeof(pe::IMAGE_DELAY_LOAD32);
    }
    return static_cast<bufsize_t>(size);
}

//---------------------------------------------------------------------------

pe::IMAGE_IMPORT_BY_NAME* DelayImpEntryWrapper::getFirstImpByNamePtr()
{
    bool isOk = false;
    uint64_t value = this->getNumValue(INT, &isOk);
    if(!isOk) return NULL;

    Executable::addr_type aT = containsAddrType(INT);
    BYTE *ptr = m_Exe->getContentAt(value, aT, sizeof(pe::IMAGE_IMPORT_BY_NAME));
    return (pe::IMAGE_IMPORT_BY_NAME*) ptr;
}

bool DelayImpEntryWrapper::wrap()
{
    clear();

    for (size_t i = 0; i < ImportBaseEntryWrapper::EntriesLimit;  i++) { //

        DelayImpFuncWrapper* entry = new DelayImpFuncWrapper(this->m_Exe, this, i);
        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        bool isOk = false;
        uint64_t val = entry->getNumValue(DelayImpFuncWrapper::NAMETHUNK_ADDR, &isOk);
        if (!isOk || val == INVALID_ADDR || val == 0) {
            delete entry;
            break;
        }
        this->entries.push_back(entry);

        DelayImpDirWrapper *impDir = dynamic_cast<DelayImpDirWrapper*>(this->parentNode);
        if (impDir) impDir->addFuncMapping(entry);
    }
    return true;
}

pe::IMAGE_DELAY_LOAD32* DelayImpEntryWrapper::dl32()
{
    if (m_Exe->getBitMode() != Executable::BITS_32) return NULL;

    DelayImpDirWrapper *parent = dynamic_cast<DelayImpDirWrapper*>(this->parentNode);
    if (!parent) return NULL;

    const size_t DL_SIZE = sizeof(pe::IMAGE_DELAY_LOAD32);
    pe::IMAGE_DELAY_LOAD32* first = (pe::IMAGE_DELAY_LOAD32*) parent->firstDelayLd(DL_SIZE);
    if (!first) return NULL;

    uint64_t descAddr = parent->getOffset(first);
    if (descAddr == INVALID_ADDR) return NULL;

    uint64_t entryOffset = descAddr + (this->entryNum * DL_SIZE);
    if (entryOffset == INVALID_ADDR) return NULL;

    BYTE *content =  this->m_Exe->getContentAt(entryOffset, Executable::RAW, DL_SIZE);
    if (!content) return NULL;

    return (pe::IMAGE_DELAY_LOAD32*)content;
}

pe::IMAGE_DELAY_LOAD64* DelayImpEntryWrapper::dl64()
{
    if (m_Exe->getBitMode() != Executable::BITS_64) return NULL;

    DelayImpDirWrapper *parent = dynamic_cast<DelayImpDirWrapper*>(this->parentNode);
    if (!parent) return NULL;

    const size_t DL_SIZE = sizeof(pe::IMAGE_DELAY_LOAD64);
    pe::IMAGE_DELAY_LOAD64* first = (pe::IMAGE_DELAY_LOAD64*) parent->firstDelayLd(DL_SIZE);
    if (!first) return NULL;

    uint64_t descAddr = parent->getOffset(first);
    if (descAddr == INVALID_ADDR) return NULL;

    uint64_t entryOffset = descAddr + (this->entryNum * DL_SIZE);
    if (entryOffset == INVALID_ADDR) return NULL;

    BYTE *content =  this->m_Exe->getContentAt(entryOffset, Executable::RAW, DL_SIZE);
    if (!content) return NULL;

    return (pe::IMAGE_DELAY_LOAD64*)content;
}

void* DelayImpEntryWrapper::getPtr()
{
    void *ptr = dl64();
    if (ptr) return ptr;

    ptr = dl32();
    return ptr;
}

bufsize_t DelayImpEntryWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    if (m_Exe->getBitMode() == Executable::BITS_64) {
        return sizeof(pe::IMAGE_DELAY_LOAD64);
    }
    return sizeof(pe::IMAGE_DELAY_LOAD32);
}

QString DelayImpEntryWrapper::getName()
{
    char* name = getLibraryName();
    if (!name) return "";
    return QString(name);
}

char* DelayImpEntryWrapper::getLibraryName()
{
    bool isOk = false;
    uint64_t offset = this->getNumValue(DelayImpEntryWrapper::NAME, &isOk);
    if (!isOk) return NULL;

    Executable::addr_type aT = containsAddrType(NAME);
    if (aT == Executable::NOT_ADDR) return NULL;

    char *ptr = (char*) m_Exe->getContentAt(offset, aT, 1);
    if (!ptr) return NULL;

    return ptr;
}

void* DelayImpEntryWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::IMAGE_DELAY_LOAD32* dLd = (pe::IMAGE_DELAY_LOAD32*) this->getPtr();
    if (dLd == NULL) return NULL;

    switch (fId) {
        case ATTRS : return &dLd->grAttrs;
        case NAME : return &dLd->szName;
        case MOD : return &dLd->phmod;
        case IAT : return &dLd->pIAT;
        case INT : return &dLd->pINT;
        case BOUND_IAT : return &dLd->pBoundIAT;
        case UNLOAD_IAT : return &dLd->pUnloadIAT;
        case TIMESTAMP : return &dLd->dwTimestamp;
    }
    return this->getPtr();
}

QString DelayImpEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case ATTRS : return "Attributes";
        case NAME : return "Name Addr.";
        case MOD : return "ModuleHandle";
        case IAT : return "IAT";
        case INT : return "ImportNameTable";
        case BOUND_IAT : return "BoundIAT";
        case UNLOAD_IAT : return "UnloadIAT";
        case TIMESTAMP : return "Timestamp";
    }
    return getName();
}

Executable::addr_type DelayImpEntryWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case NAME :
        case MOD :
        case IAT :
        case INT :
        case BOUND_IAT :
        case UNLOAD_IAT :
        {
            bool isOk = false;
            uint64_t offset = this->getNumValue(fieldId, &isOk);
            if (!isOk) return Executable::NOT_ADDR;

            return m_Exe->detectAddrType(offset, Executable::RVA);
        }
    }
    return Executable::NOT_ADDR;
}

//---------------------------------------------------------------------------

bool DelayImpFuncWrapper::isByOrdinal()
{
    bool isOk = false;
    uint64_t addr = this->getNumValue(NAMETHUNK_ADDR, &isOk);
    if (!isOk || addr == INVALID_ADDR) return false;

    uint64_t shiftedVal = getOrdinal();
    if (shiftedVal == addr) {
        return false;
    }
    return true;
}

uint64_t DelayImpFuncWrapper::getOrdinal()
{
    bool isOk = false;
    uint64_t addr = this->getNumValue(NAMETHUNK_ADDR, &isOk);
    if (!isOk || addr == INVALID_ADDR) return INVALID_ADDR;

    size_t fieldSize = this->ptrLen() * 8; // in bits!
    size_t shiftSize = (sizeof(addr) - fieldSize) + 1;

    uint64_t shiftedVal = (addr << shiftSize) >> shiftSize;
    return shiftedVal;
}

char* DelayImpFuncWrapper::getFunctionName()
{
    //check
    if (isByOrdinal() == true) return NULL;

    IMAGE_IMPORT_BY_NAME* ptr = getImportByNamePtr();
    if (ptr == NULL) return NULL;

    return (char*) &ptr->Name;
}

uint16_t DelayImpFuncWrapper::getHint()
{
    if (isByOrdinal() == true) return 0;

    IMAGE_IMPORT_BY_NAME* ptr = getImportByNamePtr();
    if (ptr == NULL) return 0;

    return ptr->Hint;
}

void* DelayImpFuncWrapper::getFieldPtr(size_t fId, size_t subField)
{
    if (this->parentDir == NULL) return NULL;

    pe::IMAGE_DELAY_LOAD32* dLd32 = parentDir->dl32();
    pe::IMAGE_DELAY_LOAD64* dLd64 = parentDir->dl64();

    if (dLd32 == NULL && dLd64 == NULL) return NULL;

    uint64_t offset = INVALID_ADDR;
    bool isOk = false;

    switch (fId) {
        case NAMETHUNK_ADDR :
            offset = parentDir->getNumValue(DelayImpEntryWrapper::INT, &isOk); break;
        case IAT_ADDR :
            offset = parentDir->getNumValue(DelayImpEntryWrapper::IAT, &isOk); break;
        case BOUND_IAT_ADDR :
            offset = parentDir->getNumValue(DelayImpEntryWrapper::BOUND_IAT, &isOk); break;
        case UNLOAD_IAT_ADDR :
            offset = parentDir->getNumValue(DelayImpEntryWrapper::UNLOAD_IAT, &isOk); break;
        default: return getPtr();
    }

    if (isOk && offset != INVALID_ADDR && offset != 0) {
        offset += (this->entryNum * ptrLen());
        Executable::addr_type aT = m_Exe->detectAddrType(offset, Executable::RVA);
        BYTE *ptr = m_Exe->getContentAt(offset, aT, static_cast<bufsize_t>(ptrLen()));
        return ptr;
    }
    return NULL;
}

uint64_t DelayImpFuncWrapper::callVia()
{
    bool isOk = false;
    uint64_t offset = parentDir->getNumValue(DelayImpEntryWrapper::IAT, &isOk);
    if (isOk && offset != INVALID_ADDR && offset != 0) {
        offset += (this->entryNum * ptrLen());
        return offset;
    }
    return INVALID_ADDR;

}

QString DelayImpFuncWrapper::getFieldName(size_t fId)
{
    switch (fId) {
        case NAMETHUNK_ADDR : return "Name Addr.";
        case IAT_ADDR : return "IAT Addr.";
        case BOUND_IAT_ADDR : return "Bound IAT";
        case UNLOAD_IAT_ADDR : return "Unload IAT";
    }
    return "";
}

Executable::addr_type DelayImpFuncWrapper::containsAddrType(size_t fId, size_t subField)
{
    bool isOk = false;
    uint64_t offset = this->getNumValue(fId, &isOk);
    if (!isOk || offset == INVALID_ADDR || offset == 0) return Executable::NOT_ADDR;

    Executable::addr_type aT = m_Exe->detectAddrType(offset, Executable::RVA);
    switch (fId) {
        case IAT_ADDR :
        case NAMETHUNK_ADDR :
        case BOUND_IAT_ADDR :
        case UNLOAD_IAT_ADDR :
            return aT;
    }
    return Executable::NOT_ADDR;
}

IMAGE_IMPORT_BY_NAME* DelayImpFuncWrapper::getImportByNamePtr()
{
    bool isOk = false;
    uint64_t addr = this->getNumValue(NAMETHUNK_ADDR, &isOk);
    if (!isOk || addr == INVALID_ADDR) return NULL;

    Executable::addr_type aT = m_Exe->detectAddrType(addr, Executable::RVA);
    BYTE *ptr = m_Exe->getContentAt(addr, aT, sizeof(pe::IMAGE_IMPORT_BY_NAME));
    return (pe::IMAGE_IMPORT_BY_NAME*) ptr;
}

