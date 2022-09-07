#pragma once

#include "PENodeWrapper.h"

#include "pe_formats.h"

#include <map>
#include <vector>

class FileHdrWrapper : public PEElementWrapper
{
public:
    /* fields :*/
    enum FieldID {
        NONE = -1,
        MACHINE = 0,
        SEC_NUM,
        TIMESTAMP,
        SYMBOL_PTR,
        SYMBOL_NUM,
        OPTHDR_SIZE,
        CHARACT,
        FIELD_COUNTER
    };

    static std::map<DWORD, QString> s_fHdrCharact;
    static std::map<DWORD, QString> s_machine;

    static void initCharact();
    static std::vector<DWORD> splitCharact(DWORD characteristics);
    static QString translateCharacteristics(DWORD charact);

    static void initMachine();
    static QString translateMachine(DWORD val);

    FileHdrWrapper(PEFile *pe) : PEElementWrapper(pe), hdr(NULL) {}
    bool wrap() { hdr = NULL; getPtr(); return true; }

    /* full structure boundaries */
    virtual void* getPtr();
    virtual bufsize_t getSize() { return sizeof(IMAGE_FILE_HEADER); }
    virtual QString getName() { return "File Hdr"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundaries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    virtual QString translateFieldContent(size_t fieldId);
private:
    IMAGE_FILE_HEADER* hdr;
};

