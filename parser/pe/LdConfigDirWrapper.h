#pragma once
#include "../ExeNodeWrapper.h"
#include "pe_formats.h"
/*
typedef struct {
    DWORD   Size;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   GlobalFlagsClear;
    DWORD   GlobalFlagsSet;
    DWORD   CriticalSectionDefaultTimeout;
    DWORD   DeCommitFreeBlockThreshold;
    DWORD   DeCommitTotalFreeThreshold;
    DWORD   LockPrefixTable;            // VA
    DWORD   MaximumAllocationSize;
    DWORD   VirtualMemoryThreshold;
    DWORD   ProcessHeapFlags;
    DWORD   ProcessAffinityMask;
    WORD    CSDVersion;
    WORD    Reserved1;
    DWORD   EditList;                   // VA
    DWORD   SecurityCookie;             // VA
    DWORD   SEHandlerTable;             // VA
    DWORD   SEHandlerCount;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

*/

class LdConfigDirWrapper : public ExeNodeWrapper
{
public:

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
        PROC_HEAP_FLAGS,
        PROC_AFF_MASK,
        CSD_VER,
        RESERVED1,
        EDIT_LIST,
        SEC_COOKIE,
        SEH_TABLE,
        SEH_COUNT,
        FIELD_COUNTER
    };

    LdConfigDirWrapper(Executable* pe)
        :  ExeNodeWrapper(pe) { wrap(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "LdConfig"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    void *firstSEHPtr();
    size_t getSEHSize() { return sizeof(DWORD); } //TODO: check how it is for PE64

private:
    pe::IMAGE_LOAD_CONFIG_DIRECTORY32* ldConf32();
    pe::IMAGE_LOAD_CONFIG_DIRECTORY64* ldConf64();
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

    LdConfigEntryWrapper(Executable* pe, LdConfigDirWrapper *parentDir, uint32_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundatries
    virtual void* getPtr();
    virtual bufsize_t getSize();

    virtual QString getName() { return "SEHandler"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE) { return getPtr();  }
    virtual QString getFieldName(size_t fieldId) { return getName(); }
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::RVA; }

private:
    LdConfigDirWrapper* parentDir;

};

