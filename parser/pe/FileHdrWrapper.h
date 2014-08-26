#pragma once

#include "PENodeWrapper.h"

#include "pe_formats.h"
using namespace pe;

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

    FileHdrWrapper(PEFile *pe) : PEElementWrapper(pe), hdr(NULL) {}
    bool wrap() { hdr = NULL; getPtr(); return true; }

    /* full structure boundatries */
    virtual void* getPtr();
    virtual bufsize_t getSize() { return sizeof(IMAGE_FILE_HEADER); }
    virtual QString getName() { return "File Hdr"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);
private:
    IMAGE_FILE_HEADER* hdr;
};

