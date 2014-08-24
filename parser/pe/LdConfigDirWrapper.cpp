#include "LdConfigDirWrapper.h"
#include "PEFile.h"

bufsize_t LdConfigDirWrapper::getLdConfigDirSize()
{
    bufsize_t dirSize = 0;

    if (m_Exe->getBitMode() == Executable::BITS_32) {
        dirSize = sizeof(pe::IMAGE_LOAD_CONFIG_DIRECTORY32);
    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        dirSize = sizeof(pe::IMAGE_LOAD_CONFIG_DIRECTORY64);
    }
    return dirSize;
}

bufsize_t LdConfigDirWrapper::getW81partSize()
{
    bufsize_t dirSize = 0;

    if (m_Exe->getBitMode() == Executable::BITS_32) {
        dirSize = sizeof(pe::IMAGE_LOAD_CONFIG_D32_W81);
    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        dirSize = sizeof(pe::IMAGE_LOAD_CONFIG_D64_W81);
    }
    return dirSize;
}

void* LdConfigDirWrapper::getLdConfigDirPtr()
{
    offset_t rva = getDirEntryAddress();

    bufsize_t dirSize = getLdConfigDirSize();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, dirSize);
    return ptr;
}

pe::IMAGE_LOAD_CONFIG_DIRECTORY32* LdConfigDirWrapper::ldConf32()
{
    if (m_Exe->getBitMode() != Executable::BITS_32) return NULL;
    return (pe::IMAGE_LOAD_CONFIG_DIRECTORY32*) getLdConfigDirPtr();
}

pe::IMAGE_LOAD_CONFIG_DIRECTORY64* LdConfigDirWrapper::ldConf64()
{
    if (m_Exe->getBitMode() != Executable::BITS_64) return NULL;
    return (pe::IMAGE_LOAD_CONFIG_DIRECTORY64*) getLdConfigDirPtr();
}

void* LdConfigDirWrapper::getW81part()
{
    void *ldPtr = getLdConfigDirPtr();
    if (ldPtr == NULL) return NULL;

    size_t dirSize = getLdConfigDirSize();

    size_t realSize = 0;
    if (m_Exe->getBitMode() == Executable::BITS_32) {
        realSize = ((pe::IMAGE_LOAD_CONFIG_DIRECTORY32*) ldPtr)->Size;

    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        realSize = ((pe::IMAGE_LOAD_CONFIG_DIRECTORY64*) ldPtr)->Size;
    }

    if (realSize <= dirSize) return NULL;

    if (realSize > dirSize) {
        offset_t offset = this->getOffset(ldPtr);
        if (offset == INVALID_ADDR) return NULL;

        offset += dirSize;
        return m_Exe->getContentAt(offset, getW81partSize());
    }
    return NULL;
}

pe::IMAGE_LOAD_CONFIG_D32_W81* LdConfigDirWrapper::getW81part32()
{
    if (m_Exe->getBitMode() != Executable::BITS_32) return NULL;
    return (pe::IMAGE_LOAD_CONFIG_D32_W81*) getW81part();
}

pe::IMAGE_LOAD_CONFIG_D64_W81* LdConfigDirWrapper::getW81part64()
{
    if (m_Exe->getBitMode() != Executable::BITS_64) return NULL;
    return (pe::IMAGE_LOAD_CONFIG_D64_W81*) getW81part();
}

bool LdConfigDirWrapper::wrap()
{
    clear();
    if (!getPtr()) return false;

    bool isOk = false;
    size_t count = this->getNumValue(SEH_COUNT, &isOk);
    if (!isOk) return false;

    for (int i = 0 ; i < count; i++) {
        LdConfigEntryWrapper *entry = new LdConfigEntryWrapper(m_Exe, this, i);
        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        this->entries.push_back(entry);
    }
    return true;
}

void* LdConfigDirWrapper::getPtr()
{
    void *ptr = ldConf32();
    if (ptr == NULL) ptr = ldConf64();
    return ptr;
}

void* LdConfigDirWrapper::firstSEHPtr()
{
    bool isOk = false;
    uint64_t offset = this->getNumValue(SEH_TABLE, &isOk);
    if (!isOk) return NULL;

    Executable::addr_type aT = containsAddrType(SEH_TABLE);
    if (aT == Executable::NOT_ADDR) return NULL;

    bufsize_t handlerSize = static_cast<bufsize_t>(this->getSEHSize());
    char *ptr = (char*) m_Exe->getContentAt(offset, aT, handlerSize);
    if (!ptr) return NULL;

    return ptr;
}

bufsize_t LdConfigDirWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    bufsize_t totalSize = getLdConfigDirSize();

    if (this->isW81()) totalSize += this->getW81partSize();
    return totalSize;
}

void* LdConfigDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::IMAGE_LOAD_CONFIG_DIRECTORY32* ld32 = ldConf32();
    pe::IMAGE_LOAD_CONFIG_DIRECTORY64* ld64 = ldConf64();
    if (ld64 == NULL && ld32 == NULL) return NULL;

    pe::IMAGE_LOAD_CONFIG_D32_W81* p32 = getW81part32();
    pe::IMAGE_LOAD_CONFIG_D64_W81* p64 = getW81part64();
    if (p32 == NULL && p64 == NULL) {
        if (fId > SEH_COUNT) this->getPtr();
    }

    switch (fId) {
        case SIZE : return (ld32) ? (void*) &ld32->Size :  (void*) &ld64->Size;
        case TIMEST : return (ld32) ? (void*) &ld32->TimeDateStamp : (void*) &ld64->TimeDateStamp ;
        case MAJOR_VER : return (ld32) ? (void*) &ld32->MajorVersion : (void*) &ld64->MajorVersion ;
        case MINOR_VER : return (ld32) ? (void*) &ld32->MinorVersion : (void*) &ld64->MinorVersion ;
        case GLOBAL_FLAGS_CLEAR : return (ld32) ? (void*) &ld32->GlobalFlagsClear :  (void*) &ld64->GlobalFlagsClear ;
        case GLOBAL_FLAGS_SET : return (ld32) ? (void*) &ld32->GlobalFlagsSet :  (void*) &ld64->GlobalFlagsSet ;
        case CRITICAT_SEC_TIMEOUT : return (ld32) ? (void*) &ld32->CriticalSectionDefaultTimeout:  (void*) &ld64->CriticalSectionDefaultTimeout ;
        case DECOMMIT_FREE : return (ld32) ? (void*) &ld32->DeCommitFreeBlockThreshold : (void*) &ld64->DeCommitFreeBlockThreshold ;

        case DECOMMIT_TOTAL : return (ld32) ? (void*) &ld32->DeCommitTotalFreeThreshold :  (void*) &ld64->DeCommitTotalFreeThreshold ;
        case LOCK_PREFIX : return (ld32) ? (void*) &ld32->LockPrefixTable :  (void*) &ld64->LockPrefixTable ;
        case MAX_ALLOC : return (ld32) ? (void*) &ld32->MaximumAllocationSize :  (void*) &ld64->MaximumAllocationSize ;
        case VIRTUAL_MEM : return (ld32) ? (void*) &ld32->VirtualMemoryThreshold :  (void*) &ld64->VirtualMemoryThreshold ;
        case PROC_HEAP_FLAGS : return (ld32) ? (void*) &ld32->ProcessHeapFlags :  (void*) &ld64->ProcessHeapFlags ;
        case PROC_AFF_MASK : return (ld32) ? (void*) &ld32->ProcessAffinityMask :  (void*) &ld64->ProcessAffinityMask ;

        case CSD_VER : return (ld32) ? (void*) &ld32->CSDVersion :  (void*) &ld64->CSDVersion ;
        case RESERVED1 : return (ld32) ? (void*) &ld32->Reserved1 :  (void*) &ld64->Reserved1 ;
        case EDIT_LIST : return (ld32) ? (void*) &ld32->EditList :  (void*) &ld64->EditList ;
        case SEC_COOKIE : return (ld32) ? (void*) &ld32->SecurityCookie :  (void*) &ld64->SecurityCookie ;
        case SEH_TABLE : return (ld32) ? (void*) &ld32->SEHandlerTable :  (void*) &ld64->SEHandlerTable ;
        case SEH_COUNT : return (ld32) ? (void*) &ld32->SEHandlerCount :  (void*) &ld64->SEHandlerCount ;

        // W8.1 part:
        case GUARD_CHECK : return (p32) ? (void*) &p32->GuardCFCheckFunctionPointer :  (void*) &p64->GuardCFCheckFunctionPointer;
        case RESERVED2 : return (p32) ? (void*) &p32->Reserved2 :  (void*) &p64->Reserved2;
        case GUARD_TABLE: return (p32) ? (void*) &p32->GuardCFFunctionTable :  (void*) &p64->GuardCFFunctionTable;
        case GUARD_COUNT: return (p32) ? (void*) &p32->GuardCFFunctionCount :  (void*) &p64->GuardCFFunctionCount;
        case GUARD_FLAGS: return (p32) ? (void*) &p32->GuardFlags:  (void*) &p64->GuardFlags;
    }
    return this->getPtr();
}

QString LdConfigDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case SIZE : return "Size";
        case TIMEST : return "TimeDateStamp";
        case MAJOR_VER : return "MajorVersion";
        case MINOR_VER : return "MinorVersion";
        case GLOBAL_FLAGS_CLEAR : return "GlobalFlagsClear";
        case GLOBAL_FLAGS_SET : return "GlobalFlagsSet";
        case CRITICAT_SEC_TIMEOUT : return "CriticalSectionDefaultTimeout";
        case DECOMMIT_FREE : return "DeCommitFreeBlockThreshold";
        case DECOMMIT_TOTAL : return "DeCommitTotalFreeThreshold";
        case LOCK_PREFIX : return "LockPrefixTable";
        case MAX_ALLOC : return "MaximumAllocationSize";
        case VIRTUAL_MEM : return "VirtualMemoryThreshold";
        case PROC_AFF_MASK : return "ProcessAffinityMask";
        case PROC_HEAP_FLAGS : return "ProcessHeapFlags";
        case CSD_VER : return "CSDVersion";
        case RESERVED1 : return "Reserved";
        case EDIT_LIST : return "EditList";
        case SEC_COOKIE : return "SecurityCookie";
        case SEH_TABLE : return "SEHandlerTable";
        case SEH_COUNT : return "SEHandlerCount";
        // W8.1 part :
        case GUARD_CHECK : return "GuardCFCheckFunctionPtr";
        case RESERVED2 : return "Reserved2";
        case GUARD_TABLE: return "GuardCFFunctionTable";
        case GUARD_COUNT: return "GuardCFFunctionCount";
        case GUARD_FLAGS: return "GuardFlags";
    }
    return getName();
}

Executable::addr_type LdConfigDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case LOCK_PREFIX :
        case EDIT_LIST :
        case SEC_COOKIE :
        case SEH_TABLE :
        case GUARD_CHECK :
        case GUARD_TABLE :
            return Executable::VA;
    }
    return Executable::NOT_ADDR;
}

//----------------

void* LdConfigEntryWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;
    void* first = parentDir->firstSEHPtr();
    if (first == NULL) return NULL;

    bufsize_t size = static_cast<bufsize_t>(parentDir->getSEHSize());
    offset_t offset = this->getOffset(first);
    if (offset == INVALID_ADDR) return NULL;

    offset += (this->entryNum * size);
    void *ptr = m_Exe->getContentAt(offset, Executable::RAW, size);
    return ptr;
}

bufsize_t LdConfigEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    return static_cast<bufsize_t>(parentDir->getSEHSize());
}

