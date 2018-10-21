#pragma once

#include "PENodeWrapper.h"

class RichHdrWrapper : public PEElementWrapper
{
public:
    /* fields :*/
    enum FieldID {
        NONE = -1,
        DANS_ID = 0,
        CPAD,
        COMP_ID_1,
        RICH_ID,
        CHECKSUM,
        FIELD_COUNTER
    };

    RichHdrWrapper(PEFile *pe) : PEElementWrapper(pe) { }

    /* full structure boundatries */
    virtual void* getPtr();
    virtual bufsize_t getSize() { return getPtr() ? sizeof(IMAGE_RICH_HEADER) : 0; }
    virtual QString getName() { return "Rich Hdr"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(uint32_t fieldId, uint32_t subField = FIELD_NONE);
};

