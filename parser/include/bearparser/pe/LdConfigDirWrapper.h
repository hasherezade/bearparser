#pragma once
#include "DataDirEntryWrapper.h"

#ifndef IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
#define IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000
#endif

#ifndef IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK 0xF0000000
#endif

#ifndef IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT 28
#endif

class LdConfigDirWrapper : public DataDirEntryWrapper
{
public:
    /**
    * For some reason the fields:
    * 
    ULONGLONG  ProcessAffinityMask;
    DWORD      ProcessHeapFlags;
    * 
    * are flipped in the 64 bit structure
    * */
    enum LdConfigDirFID {
        NONE = FIELD_NONE,
        SIZE,
        TIMEST,
        MAJOR_VER,
        MINOR_VER,
        GLOBAL_FLAGS_CLEAR,
        GLOBAL_FLAGS_SET,
        CRITICAT_SEC_TIMEOUT,
        DECOMMIT_FREE,
        DECOMMIT_TOTAL,
        LOCK_PREFIX,
        MAX_ALLOC,
        VIRTUAL_MEM,
        PROC_HEAP_FLAGS32, // PROC_AFF_MASK64
        PROC_AFF_MASK32, // PROC_HEAP_FLAGS32
        CSD_VER,
        DEPENDENT_LOAD_FLAGS,
        EDIT_LIST,
        SEC_COOKIE,
        SEH_TABLE,
        SEH_COUNT,
        FIELD_COUNTER_OLD, //end of old LoadConfigDir
        GUARD_CHECK = FIELD_COUNTER_OLD,
        GUARD_DISPATCH = GUARD_CHECK + 1,
        GUARD_TABLE,
        GUARD_COUNT,
        GUARD_FLAGS,
        FIELD_COUNTER_W81, //end of old LoadConfigDir Win8.1
        CODE_INTEGRITY_FLAGS = FIELD_COUNTER_W81, //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Flags
        CODE_INTEGRITY_CATALOG = CODE_INTEGRITY_FLAGS + 1,  //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Catalog
        CODE_INTEGRITY_CATALOG_OFFSET, //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.CatalogOffset
        CODE_INTEGRITY_RESERVED, //IMAGE_LOAD_CONFIG_CODE_INTEGRITY.Reserved
        GUARD_ADDR_IAT_ENTRY_TABLE,
        GUARD_ADDR_IAT_ENTRY_COUNT,
        GUARD_LONG_JUMP_TABLE,
        GUARD_LONG_JUMP_COUNT,
        DYNAMIC_VAL_RELOC,
        CHPE_METADATA_PTR,
        GUARD_FAILURE_ROUTINE,
        GUARD_FAILURE_ROUTINE_FUNC_PTR,
        DYNAMIC_VAL_RELOC_TABLE_OFFSET,
        DYNAMIC_VAL_RELOC_TABLE_SECTION,
        RESERVED2,
        GUARD_VERIFY_STACK_PTR,
        HOT_PATCH_TABLE_OFFSET,
        RESERVED3,
        ENCLAVE_CONFIG_PTR,
        VOLATILE_METADATA_PTR,
        FIELD_COUNTER //end of LoadConfigDir Win10
    };

    LdConfigDirWrapper(PEFile* pe)
        : DataDirEntryWrapper(pe, pe::DIR_LOAD_CONFIG) { wrap(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "LdConfig"; }

    virtual size_t getFieldsCount()
    {
        bool is32b = (m_Exe->getBitMode() == Executable::BITS_32) ? true : false;
        size_t fId = 0;
        for (fId = 0; fId <= FIELD_COUNTER; fId++) {
            void* ptr = getFieldPtr(fId, 0);
            if (ptr == NULL) break;
        }
        return fId;
    }

    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);
    
    virtual ExeNodeWrapper* getSubfieldWrapper(size_t parentType, size_t fieldId)
    {
        std::vector<ExeNodeWrapper*> *subList = getSubEntriesList(parentType);
        if (subList == NULL) return 0;
        return this->getEntryAt(*subList, fieldId);
    }
    
    virtual size_t getSubfieldWrapperCount(size_t parentType)
    {
        std::vector<ExeNodeWrapper*> *subList = getSubEntriesList(parentType);
        if (subList == NULL) return 0;
        return getEntriesCount(*subList);
    }

    virtual bool hasSubfieldWrapper(size_t parentType)
    {
        std::vector<ExeNodeWrapper*> *subList = getSubEntriesList(parentType);
        if (subList == NULL) return false;
        return true;
    }

    bool hasSupressionInfo()
    {
        bool isOk = false;
        bool isSupressed = false;
        uint64_t GuardFlags = this->getNumValue(GUARD_FLAGS, &isOk);
        if (isOk) {
            isSupressed = (GuardFlags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT);
        }
        return isSupressed;
    }

    size_t metadataSize()
    {
        bool isOk = false;
        uint64_t GuardFlags = this->getNumValue(GUARD_FLAGS, &isOk);
        if (!isOk) {
            return 0;
        }
        bool isSupressed = (GuardFlags & IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT);
        if (!isSupressed) {
            return 0;
        }
        const size_t metadata_fields = ((GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);
        return metadata_fields;
    }
    
protected:
    virtual void clear();
    void* firstSubEntryPtr(size_t parentId);
    
    size_t firstSubEntrySize(size_t parentId)
    {
        if (parentId == LdConfigDirWrapper::SEH_TABLE) {
            // SEH entries have no metadata
            return sizeof(DWORD);
        }
        const size_t metadata_fields = metadataSize();
        return sizeof(DWORD) + (metadata_fields * sizeof(BYTE));
    }
    
private:
    static offset_t  _getFieldDelta(bool is32b, size_t fId);
    
    bool wrapSubentriesTable(size_t parentFieldId, size_t counterFieldId);
    
    // get the size of the structure
    inline bufsize_t getLdConfigDirSize();
    
    // get the size that was defined in the header:
    bufsize_t getHdrDefinedSize();
    
    inline void* getLdConfigDirPtr();

    std::vector<ExeNodeWrapper*>* getSubEntriesList(size_t parentType)
    {
        std::map<uint32_t, std::vector<ExeNodeWrapper*> >::iterator itr = subEntriesMap.find(parentType);
        if (itr == subEntriesMap.end()){
            return NULL;
        }
        return &(itr->second);
    } 
    
    std::map<uint32_t, std::vector<ExeNodeWrapper*> > subEntriesMap;
    friend class LdConfigEntryWrapper;
};

class LdConfigEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        HANDLER_ADDR,
        METADATA,
        FIELD_COUNTER
    };

    LdConfigEntryWrapper(Executable* pe, LdConfigDirWrapper *_parentDir, size_t entryNumber, size_t _parentFieldId)
        : ExeNodeWrapper(pe, _parentDir, entryNumber), 
        parentFieldId(_parentFieldId)
    {
        this->parentDir = _parentDir;
    }

    // full structure boundaries
    virtual void* getPtr();
    virtual bufsize_t getSize();

    virtual QString getName() { return "Address"; }
    
    virtual size_t getFieldsCount()
    {
        if (!this->parentDir) return 1;
        if (this->parentFieldId == LdConfigDirWrapper::SEH_TABLE) {
            return 1;
        }
        return 1 + this->parentDir->metadataSize();
    }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    
    bufsize_t getFieldSize(size_t fieldId, size_t subField);
    
    virtual QString getFieldName(size_t fieldId)
    {
        if (fieldId == HANDLER_ADDR) {
            return "Address";
        }
        return "Metadata";
    }
    
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField)
    {
        if (fieldId == HANDLER_ADDR) {
            return Executable::RVA;
        }
        return Executable::NOT_ADDR;
    }

private:
    LdConfigDirWrapper* parentDir;
    size_t parentFieldId;
};
