#pragma once

#include "PENodeWrapper.h"

class SectionHdrWrapper : public PENodeWrapper
{
public:

    /* fields :*/
    enum SecFieldId {
        NAME = 0,
        VSIZE,
        VPTR,

        RSIZE,
        RPTR,

        RELOC_PTR,
        LINENUM_PTR,

        RELOC_NUM,
        LINENUM_NUM,

        CHARACT,
        FIELD_COUNTER
    };

    SectionHdrWrapper(PEFile *pe, uint32_t sectionNumber)
        : PENodeWrapper(pe), sectNum(sectionNumber), name(NULL), header(NULL) { wrap(); }
    bool wrap();

    /* full structure boundatries */
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);

    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField = FIELD_NONE);

    offset_t getContentOffset(Executable::addr_type aType);
    offset_t getContentEndOffset(Executable::addr_type aType, bool roundup);

    bufsize_t getContentSize(Executable::addr_type aType, bool roundup);

protected:
    bool reloadName();

    char *name;
    uint32_t sectNum;

private:
    pe::IMAGE_SECTION_HEADER *header;
};

//----

class SectHdrsWrapper : public PENodeWrapper
{
public:
    // fields :
    SectHdrsWrapper(PEFile *pe) : PENodeWrapper(pe) { wrap(); }
    bool wrap();

    // full structure boundatries
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Section Hdrs"; }
    virtual size_t getFieldsCount();

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField) { return getSubfieldSize(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId);// { return getSubFieldName(fieldId); }

    SectionHdrWrapper* getSecHdr(size_t secNum) { return (secNum >= entries.size())? NULL : dynamic_cast<SectionHdrWrapper*>(entries[secNum]); }
    SectionHdrWrapper* getSecHdrAtOffset(offset_t offset, Executable::addr_type addrType, bool roundup, bool verbose = false);

    void printSectionsMapping(Executable::addr_type aType);
    //---
    bool addEntry(ExeNodeWrapper *entry);

protected:
    bool isMyEntryType(ExeNodeWrapper *entry); // is it an entry of appropriate type

    std::map<offset_t, SectionHdrWrapper*> vSec;
    std::map<offset_t, SectionHdrWrapper*> rSec;
};

