#include "pe/LdConfigDirWrapper.h"

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

bufsize_t LdConfigDirWrapper::getW10partSize()
{
    bufsize_t dirSize = 0;

    if (m_Exe->getBitMode() == Executable::BITS_32) {
        dirSize = sizeof(pe::IMAGE_LOAD_CONFIG_D32_W10);
    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        dirSize = sizeof(pe::IMAGE_LOAD_CONFIG_D64_W10);
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

void* LdConfigDirWrapper::getW10part()
{
    void *ldPtr = getLdConfigDirPtr();
    if (ldPtr == NULL) return NULL;

    size_t dirSize = getLdConfigDirSize();

    //the size defined in the header:
    size_t realSize = 0;
    if (m_Exe->getBitMode() == Executable::BITS_32) {
        realSize = ((pe::IMAGE_LOAD_CONFIG_DIRECTORY32*) ldPtr)->Size;

    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        realSize = ((pe::IMAGE_LOAD_CONFIG_DIRECTORY64*) ldPtr)->Size;
    }
    if (realSize <= dirSize) return NULL;

    dirSize += getW81partSize(); // add the 8.1 part
    if (realSize <= dirSize) return NULL;
    void* ptr = NULL;
    // is there something more?
    if (realSize >= dirSize) {
        offset_t offset = this->getOffset(ldPtr);
        if (offset == INVALID_ADDR) return NULL;
        offset += dirSize;
        //fetch the remaining part:
        ptr = m_Exe->getContentAt(offset, getW10partSize());
    }
    return ptr;
}

pe::IMAGE_LOAD_CONFIG_D32_W10* LdConfigDirWrapper::getW10part32()
{
    if (m_Exe->getBitMode() != Executable::BITS_32) return NULL;
    return (pe::IMAGE_LOAD_CONFIG_D32_W10*) getW10part();
}

pe::IMAGE_LOAD_CONFIG_D64_W10* LdConfigDirWrapper::getW10part64()
{
    if (m_Exe->getBitMode() != Executable::BITS_64) return NULL;
    return (pe::IMAGE_LOAD_CONFIG_D64_W10*) getW10part();
}

bool LdConfigDirWrapper::wrap()
{
    clear();
    if (!getPtr()) return false;

    bool isOk = false;
    size_t count = this->getNumValue(SEH_COUNT, &isOk);
    if (!isOk) return false;

    for (size_t i = 0 ; i < count; i++) {
        LdConfigEntryWrapper *entry = new LdConfigEntryWrapper(m_Exe, this, i);
        if (!entry->getPtr()) {
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
    if (this->isW10()) totalSize += this->getW10partSize();
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
        if (fId > SEH_COUNT) return this->getPtr();
    }

    pe::IMAGE_LOAD_CONFIG_D32_W10* p10_32 = getW10part32();
    pe::IMAGE_LOAD_CONFIG_D64_W10* p10_64 = getW10part64();
    if (p10_32 == NULL && p10_64 == NULL) {
        if (fId > GUARD_FLAGS) return this->getPtr();
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
        case PROC_HEAP_FLAGS32 : //PROC_AFF_MASK64
        {
            return (ld32) ? (void*) &ld32->ProcessHeapFlags : (void*) &ld64->ProcessAffinityMask ;
        }
        case PROC_AFF_MASK32 : // PROC_HEAP_FLAGS64
        {
            return (ld32) ? (void*) &ld32->ProcessAffinityMask : (void*) &ld64->ProcessHeapFlags ;
        }
        case CSD_VER : return (ld32) ? (void*) &ld32->CSDVersion :  (void*) &ld64->CSDVersion ;
        case DEPENDENT_LOAD_FLAGS : return (ld32) ? (void*) &ld32->DependentLoadFlags :  (void*) &ld64->DependentLoadFlags ;
        case EDIT_LIST : return (ld32) ? (void*) &ld32->EditList :  (void*) &ld64->EditList ;
        case SEC_COOKIE : return (ld32) ? (void*) &ld32->SecurityCookie :  (void*) &ld64->SecurityCookie ;
        case SEH_TABLE : return (ld32) ? (void*) &ld32->SEHandlerTable :  (void*) &ld64->SEHandlerTable ;
        case SEH_COUNT : return (ld32) ? (void*) &ld32->SEHandlerCount :  (void*) &ld64->SEHandlerCount ;

        // W8.1 part:
        case GUARD_CHECK : return (p32) ? (void*) &p32->GuardCFCheckFunctionPointer : (void*) &p64->GuardCFCheckFunctionPointer;
        case GUARD_DISPATCH : return (p32) ? (void*) &p32->GuardCFDispatchFunctionPointer :  (void*) &p64->GuardCFDispatchFunctionPointer;
        case GUARD_TABLE: return (p32) ? (void*) &p32->GuardCFFunctionTable :  (void*) &p64->GuardCFFunctionTable;
        case GUARD_COUNT: return (p32) ? (void*) &p32->GuardCFFunctionCount :  (void*) &p64->GuardCFFunctionCount;
        case GUARD_FLAGS: return (p32) ? (void*) &p32->GuardFlags:  (void*) &p64->GuardFlags;

        // W10 part:
        case CODE_INTEGRITY_FLAGS: return (p10_32) ? (void*) &p10_32->CodeIntegrity.Flags : (void*) &p10_64->CodeIntegrity.Flags;
        case CODE_INTEGRITY_CATALOG: return (p10_32) ? (void*) &p10_32->CodeIntegrity.Catalog : (void*) &p10_64->CodeIntegrity.Catalog;  //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Catalog
        case CODE_INTEGRITY_CATALOG_OFFSET:  return (p10_32) ? (void*) &p10_32->CodeIntegrity.CatalogOffset : (void*) &p10_64->CodeIntegrity.CatalogOffset;  //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.CatalogOffset
        case CODE_INTEGRITY_RESERVED: return (p10_32) ? (void*) &p10_32->CodeIntegrity.Reserved : (void*) &p10_64->CodeIntegrity.Reserved; //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Reserved
        case GUARD_ADDR_IAT_ENTRY_TABLE: return (p10_32) ? (void*) &p10_32->GuardAddressTakenIatEntryTable : (void*) &p10_64->GuardAddressTakenIatEntryTable; //
        case GUARD_ADDR_IAT_ENTRY_COUNT: return (p10_32) ? (void*) &p10_32->GuardAddressTakenIatEntryCount : (void*) &p10_64->GuardAddressTakenIatEntryCount; // return "GuardAddressTakenIatEntryCount";
        case GUARD_LONG_JUMP_TABLE:  return (p10_32) ? (void*) &p10_32->GuardLongJumpTargetTable : (void*) &p10_64->GuardLongJumpTargetTable; //GuardLongJumpTargetTable";
        case GUARD_LONG_JUMP_COUNT:  return (p10_32) ? (void*) &p10_32->GuardLongJumpTargetCount : (void*) &p10_64->GuardLongJumpTargetCount; // "GuardLongJumpTargetCount";
        case DYNAMIC_VAL_RELOC:  return (p10_32) ? (void*) &p10_32->DynamicValueRelocTable : (void*) &p10_64->DynamicValueRelocTable; // "DynamicValueRelocTable";
        case CHPE_METADATA_PTR:  return (p10_32) ? (void*) &p10_32->CHPEMetadataPointer : (void*) &p10_64->CHPEMetadataPointer; // "CHPEMetadataPointer";
        case GUARD_FAILURE_ROUTINE:  return (p10_32) ? (void*) &p10_32->GuardRFFailureRoutine : (void*) &p10_64->GuardRFFailureRoutine; // "GuardRFFailureRoutine";
        case GUARD_FAILURE_ROUTINE_FUNC_PTR: return (p10_32) ? (void*) &p10_32->GuardRFFailureRoutineFunctionPointer : (void*) &p10_64->GuardRFFailureRoutineFunctionPointer;
        case DYNAMIC_VAL_RELOC_TABLE_OFFSET: return (p10_32) ? (void*) &p10_32->DynamicValueRelocTableOffset : (void*) &p10_64->DynamicValueRelocTableOffset; // "DynamicValueRelocTableOffset";
        case DYNAMIC_VAL_RELOC_TABLE_SECTION: return (p10_32) ? (void*) &p10_32->DynamicValueRelocTableSection : (void*) &p10_64->DynamicValueRelocTableSection; // "DynamicValueRelocTableSection";
        case RESERVED2:  return (p10_32) ? (void*) &p10_32->Reserved2 : (void*) &p10_64->Reserved2; // "Reserved2";
        case GUARD_VERIFY_STACK_PTR:  return (p10_32) ? (void*) &p10_32->GuardRFVerifyStackPointerFunctionPointer : (void*) &p10_64->GuardRFVerifyStackPointerFunctionPointer;
        case HOT_PATCH_TABLE_OFFSET:  return (p10_32) ? (void*) &p10_32->HotPatchTableOffset : (void*) &p10_64->HotPatchTableOffset; // "HotPatchTableOffset";
        case RESERVED3:  return (p10_32) ? (void*) &p10_32->Reserved3 : (void*) &p10_64->Reserved3; // "Reserved3";
        case ENCLAVE_CONFIG_PTR:  return (p10_32) ? (void*) &p10_32->EnclaveConfigurationPointer : (void*) &p10_64->EnclaveConfigurationPointer; // "EnclaveConfigurationPointer";
    }
    return this->getPtr();
}

QString LdConfigDirWrapper::getFieldName(size_t fieldId)
{
    if (!m_Exe) return "";
    bool is32bit = (m_Exe->getBitMode() == Executable::BITS_32);
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
        case PROC_HEAP_FLAGS32 : //PROC_AFF_MASK64
        {
            return (is32bit) ? "ProcessHeapFlags" : "ProcessAffinityMask";
        }
        case PROC_AFF_MASK32 : // PROC_HEAP_FLAGS64
        {
            return (is32bit) ? "ProcessAffinityMask" : "ProcessHeapFlags";
        }
        case CSD_VER : return "CSDVersion";
        case DEPENDENT_LOAD_FLAGS : return "DependentLoadFlags";
        case EDIT_LIST : return "EditList";
        case SEC_COOKIE : return "SecurityCookie";
        case SEH_TABLE : return "SEHandlerTable";
        case SEH_COUNT : return "SEHandlerCount";
        // W8.1 part :
        case GUARD_CHECK : return "GuardCFCheckFunctionPtr";
        case GUARD_DISPATCH : return "GuardCFDispatchFunctionPointer";
        case GUARD_TABLE: return "GuardCFFunctionTable";
        case GUARD_COUNT: return "GuardCFFunctionCount";
        case GUARD_FLAGS: return "GuardFlags";
        // W10 part:
        case CODE_INTEGRITY_FLAGS: return "CodeIntegrity.Flags"; //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Flags
        case CODE_INTEGRITY_CATALOG:  return "CodeIntegrity.Catalog";  //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Catalog
        case CODE_INTEGRITY_CATALOG_OFFSET:  return "CodeIntegrity.CatalogOffset"; //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.CatalogOffset
        case CODE_INTEGRITY_RESERVED:  return "CodeIntegrity.Reserved"; //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Reserved

        case GUARD_ADDR_IAT_ENTRY_TABLE:  return "GuardAddressTakenIatEntryTable";
        case GUARD_ADDR_IAT_ENTRY_COUNT:  return "GuardAddressTakenIatEntryCount";
        case GUARD_LONG_JUMP_TABLE:  return "GuardLongJumpTargetTable";
        case GUARD_LONG_JUMP_COUNT:  return "GuardLongJumpTargetCount";

        case DYNAMIC_VAL_RELOC:  return "DynamicValueRelocTable";
        case CHPE_METADATA_PTR:  return "CHPEMetadataPointer";
        case GUARD_FAILURE_ROUTINE:  return "GuardRFFailureRoutine";
        case GUARD_FAILURE_ROUTINE_FUNC_PTR:  return "GuardRFFailureRoutineFunctionPointer";
        case DYNAMIC_VAL_RELOC_TABLE_OFFSET:  return "DynamicValueRelocTableOffset";
        case DYNAMIC_VAL_RELOC_TABLE_SECTION: return "DynamicValueRelocTableSection";
        case RESERVED2:  return "Reserved2";
        case GUARD_VERIFY_STACK_PTR:  return "GuardRFVerifyStackPointerFunctionPointer";
        case HOT_PATCH_TABLE_OFFSET:  return "HotPatchTableOffset";
        case RESERVED3:  return "Reserved3";
        case ENCLAVE_CONFIG_PTR:  return "EnclaveConfigurationPointer";
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
        case GUARD_DISPATCH :
        case GUARD_TABLE :
        case GUARD_ADDR_IAT_ENTRY_TABLE:
        case GUARD_LONG_JUMP_TABLE:
        case DYNAMIC_VAL_RELOC:
        case GUARD_FAILURE_ROUTINE:
        case GUARD_FAILURE_ROUTINE_FUNC_PTR:
        case GUARD_VERIFY_STACK_PTR:
        case ENCLAVE_CONFIG_PTR:
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
    void *ptr = m_Exe->getContentAt(offset, Executable::RVA, size);
    return ptr;
}

bufsize_t LdConfigEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    return static_cast<bufsize_t>(parentDir->getSEHSize());
}

