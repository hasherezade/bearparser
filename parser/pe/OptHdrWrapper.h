#pragma once

#include "PENodeWrapper.h"

class OptHdrWrapper : public PEElementWrapper
{
public:
    /* fields :*/
    enum OptHdrFID {
        NONE = FIELD_NONE,
        MAGIC = 0,
        LINKER_MAJOR,
        LINKER_MINOR,
        CODE_SIZE,
        INITDATA_SIZE,
        UNINITDATA_SIZE,
        EP,
        CODE_BASE,
        DATA_BASE,

        IMAGE_BASE,
        SEC_ALIGN,
        FILE_ALIGN,
        OSVER_MAJOR,
        OSVER_MINOR,
        IMGVER_MAJOR,
        IMGVER_MINOR,
        SUBSYSVER_MAJOR,
        SUBSYSVER_MINOR,
        WIN32_VER,
        IMAGE_SIZE,
        HDRS_SIZE,
        CHECKSUM,
        SUBSYS,
        DLL_CHARACT,
        STACK_RSRV_SIZE,
        STACK_COMMIT_SIZE,
        HEAP_RSRV_SIZE,
        HEAP_COMMIT_SIZE,
        LDR_FLAGS,
        RVAS_SIZES_NUM,
        DATA_DIR,
        FIELD_COUNTER
    };
    static std::map<DWORD, QString> s_optMagic;
    static std::map<std::pair<WORD,WORD>, QString> s_osVersion;
    static std::map<DWORD, QString> s_dllCharact;
    static std::map<DWORD, QString> s_subsystem;

    static void initDllCharact();
    static std::vector<DWORD> splitDllCharact(DWORD characteristics);
    static QString translateDllCharacteristics(DWORD charact);

    static QString translateOptMagic(DWORD magic);
    static QString translateOSVersion(WORD major, WORD minor);
    static QString translateSubsystem(DWORD subsystem);
    //----

    OptHdrWrapper(PEFile *pe) : PEElementWrapper(pe), opt32(NULL), opt64(NULL) { wrap(); }
    bool wrap();

    /* full structure boundaries */
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Optional Hdr"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundaries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE);

    virtual QString translateFieldContent(size_t fieldId);

    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    Executable::exe_bits getHdrBitMode();
    IMAGE_NT_HEADERS32* nt32();
    IMAGE_NT_HEADERS64* nt64();

    //DataDirWrapper dataDir;
protected:
    IMAGE_OPTIONAL_HEADER32* opt32;
    IMAGE_OPTIONAL_HEADER64* opt64;
    std::vector<DWORD> dllCharact;
};

