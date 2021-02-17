#include "pe/LdConfigDirWrapper.h"

// offset from the beginning of the structure
#define getStructFieldOffset(STRUCT, FIELD) ((ULONGLONG) &(STRUCT.FIELD) - (ULONGLONG)&STRUCT)

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

bufsize_t LdConfigDirWrapper::getHdrDefinedSize()
{
    const offset_t rva = getDirEntryAddress();
    offset_t raw = m_Exe->rvaToRaw(rva);
    if (raw == INVALID_ADDR) return 0;
    
    offset_t offset = INVALID_ADDR;
    
    if (m_Exe->getBitMode() == Executable::BITS_32) {
        pe::IMAGE_LOAD_CONFIG_DIRECTORY32 ld = { 0 };
        offset = getStructFieldOffset(ld, Size);

    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        pe::IMAGE_LOAD_CONFIG_DIRECTORY64 ld = { 0 };
        offset = getStructFieldOffset(ld, Size);
    }
    DWORD* sizePtr = (DWORD*) m_Exe->getContentAt((raw + offset), sizeof(DWORD));
    if (!sizePtr) return 0;
    return bufsize_t(*sizePtr);
}

void* LdConfigDirWrapper::getLdConfigDirPtr()
{
    offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, this->getSize());
    return ptr;
}

bool LdConfigDirWrapper::wrapSubentriesTable(size_t parentFieldId, size_t counterFieldId)
{
    bool isOk = false;
    size_t count = this->getNumValue(counterFieldId, &isOk);
    if (!isOk) {
        return false;
    }
    for (size_t i = 0 ; i < count; i++) {
        LdConfigEntryWrapper *entry = new LdConfigEntryWrapper(m_Exe, this, i, parentFieldId);
        if (!entry || !entry->getPtr()) {
            delete entry;
            break;
        }
        this->entries.push_back(entry);
        this->subEntriesMap[parentFieldId].push_back(entry);
    }
    return isOk;
}

bool LdConfigDirWrapper::wrap()
{
    clear();
    if (!getPtr()) return false;
    //SEHandlerTable:
    wrapSubentriesTable(SEH_TABLE, SEH_COUNT);
    
    //GuardCFFunctionTable:
    wrapSubentriesTable(GUARD_TABLE, GUARD_COUNT);
    
    wrapSubentriesTable(GUARD_LONG_JUMP_TABLE, GUARD_LONG_JUMP_COUNT);
    wrapSubentriesTable(GUARD_ADDR_IAT_ENTRY_TABLE, GUARD_ADDR_IAT_ENTRY_COUNT);
    return true;
}

void* LdConfigDirWrapper::getPtr()
{
    return getLdConfigDirPtr();
}

void LdConfigDirWrapper::clear()
{
    std::map<uint32_t, std::vector<ExeNodeWrapper*> >::iterator mapItr;
    for (mapItr = this->subEntriesMap.begin(); mapItr != this->subEntriesMap.end(); mapItr++) {
        std::vector<ExeNodeWrapper*> &vec = mapItr->second;
        vec.clear();
    }
    ExeNodeWrapper::clear();
}

void* LdConfigDirWrapper::firstSubEntryPtr(size_t parentId)
{
    bool isOk = false;
    offset_t offset = this->getNumValue(parentId, &isOk);
    if (!isOk) return NULL;

    Executable::addr_type aT = containsAddrType(parentId);
    if (aT == Executable::NOT_ADDR) return NULL;

    bufsize_t handlerSize = static_cast<bufsize_t>(this->firstSubEntrySize(parentId));
    char *ptr = (char*) m_Exe->getContentAt(offset, aT, handlerSize);
    if (!ptr) return NULL;

    return ptr;
}

bufsize_t LdConfigDirWrapper::getSize()
{
    //validate the offset
    const offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, 1);
    if (!ptr) return 0;
    
    const bufsize_t hdrSize = this->getHdrDefinedSize();
    const bufsize_t structSize = getLdConfigDirSize();
    const bufsize_t totalSize = (hdrSize < structSize) ? hdrSize : structSize;
    // is the size correct
    ptr = m_Exe->getContentAt(rva, Executable::RVA, totalSize);
    if (!ptr) return 0;
    
    return totalSize;
}

offset_t  LdConfigDirWrapper::_getFieldDelta(bool is32b, size_t fId)
{
    static pe::IMAGE_LOAD_CONFIG_DIRECTORY32 ld32 = { 0 };
    static pe::IMAGE_LOAD_CONFIG_DIRECTORY64 ld64 = { 0 };

    //offset from the beginning of the IMAGE_LOAD_CONFIG_DIRECTORY_T strucure
    offset_t fieldOffset = INVALID_ADDR;
    switch (fId) {
        case SIZE : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, Size) : getStructFieldOffset(ld64, Size);
            break;
        case TIMEST : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32,TimeDateStamp) : getStructFieldOffset(ld64, TimeDateStamp);
            break;
        case MAJOR_VER :
            fieldOffset = (is32b) ? getStructFieldOffset(ld32,MajorVersion) : getStructFieldOffset(ld64, MajorVersion);
            break;
        case MINOR_VER : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, MinorVersion) : getStructFieldOffset(ld64, MinorVersion);
            break;
        case GLOBAL_FLAGS_CLEAR : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GlobalFlagsClear) : getStructFieldOffset(ld64, GlobalFlagsClear);
            break;
        case GLOBAL_FLAGS_SET : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GlobalFlagsSet) : getStructFieldOffset(ld64, GlobalFlagsSet);
            break;
        case CRITICAT_SEC_TIMEOUT : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CriticalSectionDefaultTimeout) : getStructFieldOffset(ld64, CriticalSectionDefaultTimeout);
            break;
        case DECOMMIT_FREE : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, DeCommitFreeBlockThreshold) : getStructFieldOffset(ld64, DeCommitFreeBlockThreshold);
            break;

        case DECOMMIT_TOTAL : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, DeCommitTotalFreeThreshold) : getStructFieldOffset(ld64, DeCommitTotalFreeThreshold);
            break;
        case LOCK_PREFIX : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, LockPrefixTable) : getStructFieldOffset(ld64, LockPrefixTable);
            break;
        case MAX_ALLOC : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, MaximumAllocationSize) : getStructFieldOffset(ld64, MaximumAllocationSize);
            break;
        case VIRTUAL_MEM : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, VirtualMemoryThreshold) : getStructFieldOffset(ld64, VirtualMemoryThreshold);
            break;
        case PROC_HEAP_FLAGS32 : //PROC_AFF_MASK64
        {
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, ProcessHeapFlags) : getStructFieldOffset(ld64, ProcessAffinityMask);
            break;
        }
        case PROC_AFF_MASK32 : // PROC_HEAP_FLAGS64
        {
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, ProcessAffinityMask) : getStructFieldOffset(ld64, ProcessHeapFlags);
            break;
        }
        case CSD_VER : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CSDVersion) : getStructFieldOffset(ld64, CSDVersion);
            break;
        case DEPENDENT_LOAD_FLAGS : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, DependentLoadFlags) : getStructFieldOffset(ld64, DependentLoadFlags);
            break;
        case EDIT_LIST :
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, EditList) : getStructFieldOffset(ld64, EditList);
            break;
        case SEC_COOKIE :
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, SecurityCookie) : getStructFieldOffset(ld64, SecurityCookie);
            break;
        case SEH_TABLE :
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, SEHandlerTable) : getStructFieldOffset(ld64, SEHandlerTable);
            break;
        case SEH_COUNT :
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, SEHandlerCount) : getStructFieldOffset(ld64, SEHandlerCount);
            break;

        // W8.1 part:
        case GUARD_CHECK : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardCFCheckFunctionPointer) : getStructFieldOffset(ld64, GuardCFCheckFunctionPointer);
            break;
        case GUARD_DISPATCH : 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardCFDispatchFunctionPointer) : getStructFieldOffset(ld64, GuardCFDispatchFunctionPointer);
            break;
        case GUARD_TABLE: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardCFFunctionTable) : getStructFieldOffset(ld64, GuardCFFunctionTable);
            break;
        case GUARD_COUNT: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardCFFunctionCount) : getStructFieldOffset(ld64, GuardCFFunctionCount);
            break;
        case GUARD_FLAGS: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardFlags) : getStructFieldOffset(ld64, GuardFlags);
            break;

        // W10 part:
        case CODE_INTEGRITY_FLAGS: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CodeIntegrity.Flags) : getStructFieldOffset(ld64, CodeIntegrity.Flags);
            break;
        case CODE_INTEGRITY_CATALOG: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CodeIntegrity.Catalog) : getStructFieldOffset(ld64, CodeIntegrity.Catalog);
            break;
        case CODE_INTEGRITY_CATALOG_OFFSET:  
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CodeIntegrity.CatalogOffset) : getStructFieldOffset(ld64, CodeIntegrity.CatalogOffset);
            break;
        case CODE_INTEGRITY_RESERVED: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CodeIntegrity.Reserved) : getStructFieldOffset(ld64, CodeIntegrity.Reserved);
            break;
        case GUARD_ADDR_IAT_ENTRY_TABLE: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardAddressTakenIatEntryTable) : getStructFieldOffset(ld64, GuardAddressTakenIatEntryTable);
            break;
        case GUARD_ADDR_IAT_ENTRY_COUNT: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardAddressTakenIatEntryCount) : getStructFieldOffset(ld64, GuardAddressTakenIatEntryCount);
            break;
        case GUARD_LONG_JUMP_TABLE: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardLongJumpTargetTable) : getStructFieldOffset(ld64, GuardLongJumpTargetTable);
            break;
        case GUARD_LONG_JUMP_COUNT: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardLongJumpTargetCount) : getStructFieldOffset(ld64, GuardLongJumpTargetCount);
            break;
        case DYNAMIC_VAL_RELOC:
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, DynamicValueRelocTable) : getStructFieldOffset(ld64, DynamicValueRelocTable);
            break;
        case CHPE_METADATA_PTR: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, CHPEMetadataPointer) : getStructFieldOffset(ld64, CHPEMetadataPointer);
            break;
        case GUARD_FAILURE_ROUTINE: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardRFFailureRoutine) : getStructFieldOffset(ld64, GuardRFFailureRoutine);
            break;
        case GUARD_FAILURE_ROUTINE_FUNC_PTR: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardRFFailureRoutineFunctionPointer) : getStructFieldOffset(ld64, GuardRFFailureRoutineFunctionPointer);
            break;
        case DYNAMIC_VAL_RELOC_TABLE_OFFSET: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, DynamicValueRelocTableOffset) : getStructFieldOffset(ld64, DynamicValueRelocTableOffset);
            break;
        case DYNAMIC_VAL_RELOC_TABLE_SECTION:
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, DynamicValueRelocTableSection) : getStructFieldOffset(ld64, DynamicValueRelocTableSection);
            break;
        case RESERVED2: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, Reserved2) : getStructFieldOffset(ld64, Reserved2);
            break;
        case GUARD_VERIFY_STACK_PTR: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, GuardRFVerifyStackPointerFunctionPointer) : getStructFieldOffset(ld64, GuardRFVerifyStackPointerFunctionPointer);
            break;
        case HOT_PATCH_TABLE_OFFSET: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, HotPatchTableOffset) : getStructFieldOffset(ld64, HotPatchTableOffset);
            break;
        case RESERVED3:
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, Reserved3) : getStructFieldOffset(ld64, Reserved3);
            break;
        case ENCLAVE_CONFIG_PTR:
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, EnclaveConfigurationPointer) : getStructFieldOffset(ld64, EnclaveConfigurationPointer);
            break;
        case VOLATILE_METADATA_PTR: 
            fieldOffset = (is32b) ? getStructFieldOffset(ld32, VolatileMetadataPointer) : getStructFieldOffset(ld64, VolatileMetadataPointer);
            break;
    }
    return fieldOffset;
}

void* LdConfigDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    const bool is32b = (m_Exe->getBitMode() == Executable::BITS_32) ? true : false;
    
    offset_t fieldDelta = _getFieldDelta(is32b, fId);
    if (fieldDelta != INVALID_ADDR) {
        const offset_t realSize = this->getHdrDefinedSize();
        if (fieldDelta >= realSize) {
            return getPtr();
        }
        return m_Exe->getContentAt(this->getOffset() + fieldDelta, 1);
    }
    return getPtr();
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
        case VOLATILE_METADATA_PTR:  return "VolatileMetadataPointer";
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
        case VOLATILE_METADATA_PTR: 
            return Executable::VA;
    }
    return Executable::NOT_ADDR;
}
    
//----------------

void* LdConfigEntryWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;
    
    void* first = parentDir->firstSubEntryPtr(this->parentFieldId);
    if (first == NULL) return NULL;
    bufsize_t fieldSize = static_cast<bufsize_t>(parentDir->firstSubEntrySize(this->parentFieldId));
    if (fieldSize == 0) return NULL;
    
    offset_t offset = this->getOffset(first);
    if (offset == INVALID_ADDR) return NULL;
    
    //offset from the beginning:
    offset_t fieldOffset = (this->entryNum * fieldSize);
    offset += fieldOffset;
    void *ptr = m_Exe->getContentAt(offset, Executable::RAW, fieldSize);
    return ptr;
}

bufsize_t LdConfigEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    if (!getPtr()) return 0;
    bufsize_t size = static_cast<bufsize_t>(parentDir->firstSubEntrySize(this->parentFieldId));
    return size;
}

void* LdConfigEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    void* ptr = getPtr();
    if (!ptr) return NULL;

    if (fieldId == NONE) {
        return ptr;
    }
    size_t counter = getFieldsCount();
    if (fieldId >= counter) return NULL;
    if (fieldId == HANDLER_ADDR) {
        return ptr;
    }
    return (void*)((ULONGLONG)ptr + sizeof(DWORD));
}

bufsize_t LdConfigEntryWrapper::getFieldSize(size_t fieldId, size_t subField)
{
    size_t count = this->getFieldsCount();
    if (fieldId >= count) {
        return 0;
    }
    if (fieldId == HANDLER_ADDR) {
        return sizeof(DWORD);
    }
    return sizeof(BYTE);
}
