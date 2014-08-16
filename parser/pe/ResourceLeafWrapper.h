#pragma once

#define TOP_ENTRY_ROOT (-1)

#include "../ExeNodeWrapper.h"

#include <map>
#include <vector>
#include "pe_formats.h"

class ResourceLeafWrapper : public ExeNodeWrapper
{
    public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        OFFSET_TO_DATA,
        DATA_SIZE,
        CODE_PAGE,
        RESERVED,
        FIELD_COUNTER
    };

    ResourceLeafWrapper(Executable *pe, uint64_t rawOffset, long topEntryId)
        : ExeNodeWrapper(pe), offset(rawOffset), topEntryID(topEntryId){ }

    virtual ~ResourceLeafWrapper() { }

    virtual void* getPtr() { return leafEntryPtr(); }
    virtual bufsize_t getSize() { return sizeof(pe::IMAGE_RESOURCE_DATA_ENTRY); }

    virtual QString getName() { return "Resource Data"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return (fieldId == OFFSET_TO_DATA) ? Executable::RVA : Executable::NOT_ADDR; }

    pe::IMAGE_RESOURCE_DATA_ENTRY *leafEntryPtr();

    Executable* getExe() { return this->m_Exe; }

protected:
    uint64_t offset;
    long topEntryID;
    //ResourceEntryWrapper* parentEntry;
};

