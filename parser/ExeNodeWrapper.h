#pragma once

#include "ExeElementWrapper.h"
#include <vector>

const size_t INVALID_ENTRYNUM = (-1);

class ExeNodeWrapper : public ExeElementWrapper
{
public:
    ExeNodeWrapper(Executable *pe, ExeNodeWrapper* parent = NULL);
    ExeNodeWrapper(Executable *pe, ExeNodeWrapper* parent, size_t entryNumber);

    virtual ~ExeNodeWrapper() { clear(); }

    virtual bool wrap() { return true; }
    virtual ExeNodeWrapper* getEntryAt(size_t fieldId);
    virtual size_t getEntriesCount() { return entries.size(); }
    virtual size_t getEntriesNum() { return entries.size(); }
    virtual size_t getSubFieldsCount() { return (this->entries.size() == 0) ? 0 : this->entries[0]->getFieldsCount(); }

    virtual ExeNodeWrapper* getParentNode() { return parentNode; }
    size_t getEntryId() { return entryNum; }

    virtual void* getSubfieldPtr(size_t fieldId, size_t subField);
    virtual bufsize_t getSubfieldSize(size_t fieldId, size_t subField);
    virtual QString getSubfieldName(size_t fieldId, size_t subField);

    virtual QString getFieldName(size_t fieldId) = 0;
    //---
    virtual bool canAddEntry();
    virtual bool addEntry(ExeNodeWrapper *entry);

protected:
    virtual void clear();
    virtual bool isMyEntryType(ExeNodeWrapper *entry); // is it an entry of appropriate type

    ExeNodeWrapper* parentNode;
    size_t entryNum;

    std::vector<ExeNodeWrapper*> entries; // children
};

