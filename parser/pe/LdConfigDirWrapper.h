#pragma once
#include "DataDirEntryWrapper.h"

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
        FIELD_COUNTER, //end of old LoadConfigDir
        GUARD_CHECK = FIELD_COUNTER,
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
	FIELD_COUNTER_W10 //end of old LoadConfigDir Win10
    };

    LdConfigDirWrapper(PEFile* pe)
        :  DataDirEntryWrapper(pe, pe::DIR_LOAD_CONFIG) { wrap(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "LdConfig"; }
    virtual size_t getFieldsCount() { return (isW81()) ? FIELD_COUNTER_W81 : FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    void *firstSEHPtr();
    size_t getSEHSize() { return sizeof(DWORD); } //TODO: check how it is for PE64

    bool isW81() { return (this->getW81part() != NULL); }
    bool isW10() { return (this->getW10part() != NULL); }
private:
    inline bufsize_t getLdConfigDirSize();
    inline void* getLdConfigDirPtr();
    pe::IMAGE_LOAD_CONFIG_DIRECTORY32* ldConf32();
    pe::IMAGE_LOAD_CONFIG_DIRECTORY64* ldConf64();

    inline bufsize_t getW81partSize();
    void* getW81part();
    pe::IMAGE_LOAD_CONFIG_D32_W81* getW81part32();
    pe::IMAGE_LOAD_CONFIG_D64_W81* getW81part64();

    inline bufsize_t getW10partSize();
    void* getW10part();
    pe::IMAGE_LOAD_CONFIG_D32_W10* getW10part32();
    pe::IMAGE_LOAD_CONFIG_D64_W10* getW10part64();
};


class LdConfigEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        SEHANDLER_ADDR,
        FIELD_COUNTER
    };

    LdConfigEntryWrapper(Executable* pe, LdConfigDirWrapper *parentDir, size_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundaries
    virtual void* getPtr();
    virtual bufsize_t getSize();

    virtual QString getName() { return "SEHandler"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE) { return getPtr();  }
    virtual QString getFieldName(size_t fieldId) { return getName(); }
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::RVA; }

private:
    LdConfigDirWrapper* parentDir;

};

