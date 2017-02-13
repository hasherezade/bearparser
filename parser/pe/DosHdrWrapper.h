#pragma once

#include "../ExeElementWrapper.h"
#include "../Executable.h"

#include "pe_formats.h"

class DosHdrWrapper : public ExeElementWrapper
{
public:
    /* fields :*/
    enum DosFieldId {
        NONE = FIELD_NONE,
        MAGIC = 0,
        CBLP,
        CP,
        CRLC,
        CPARHDR,
        MINALLOC,
        MAXALLOC,
        SS,
        SP,
        CSUM,
        IP,
        CS,
        LFARLC,
        OVNO,
        RES,
        OEMID,
        OEMINFO,
        RES2,
        LFNEW,
        FIELD_COUNTER
    };

    DosHdrWrapper(Executable *dosExe) : ExeElementWrapper(dosExe) { }

    /* full structure boundatries */
    virtual void* getPtr() { return m_Exe->getContent(); }
    virtual bufsize_t getSize() { return sizeof(IMAGE_DOS_HEADER); }
    virtual QString getName() { return "DOS Hdr"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);
};

