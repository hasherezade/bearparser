#pragma once

#include "PENodeWrapper.h"
#include "pe_undoc.h"

class RichHdrWrapper : public PEElementWrapper
{
public:
    /* fields :*/
    enum FieldID {
        NONE = -1,
        DANS_ID = 0,
        CPAD0,
        CPAD1,
        CPAD2,
        COMP_ID_1,
        RICH_ID,
        CHECKSUM,
        FIELD_COUNTER
    };

    RichHdrWrapper(PEFile *pe)
        : PEElementWrapper(pe), richSign(NULL), dansHdr(NULL), compIdCounter(0) { wrap(); }

    size_t compIdCount();

    virtual bool wrap();
    /* full structure boundaries */
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Rich Hdr"; }
    virtual size_t getFieldsCount();

    /* specific field boundaries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    //virtual bufsize_t getFieldSize(size_t fieldId, size_t subField);
    virtual QString translateFieldContent(size_t fieldId);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(uint32_t fieldId, uint32_t subField = FIELD_NONE);

protected:
    pe::RICH_SIGNATURE* richSign;
    pe::RICH_DANS_HEADER* dansHdr;
    size_t compIdCounter;
};

