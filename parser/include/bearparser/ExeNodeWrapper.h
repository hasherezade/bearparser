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
    virtual void reloadMapping() {}

    virtual ExeNodeWrapper* getEntryAt(size_t fieldId);
    virtual size_t getEntriesCount() { return getEntriesCount(this->entries); }
    virtual size_t getEntriesNum() { return getEntriesCount(this->entries); }
    virtual size_t getSubFieldsCount() { return (this->entries.size() == 0) ? 0 : this->entries[0]->getFieldsCount(); }

    virtual ExeNodeWrapper* getParentNode() { return parentNode; }
    size_t getEntryId() { return entryNum; }

    virtual void* getSubfieldPtr(size_t fieldId, size_t subField);
    virtual bufsize_t getSubfieldSize(size_t fieldId, size_t subField);
    virtual QString getSubfieldName(size_t fieldId, size_t subField);

    virtual QString getFieldName(size_t fieldId) = 0;
    //---
    virtual bool canAddEntry();
    
    virtual ExeNodeWrapper* addEntry(ExeNodeWrapper *entry);
    ExeNodeWrapper* getLastEntry();
    virtual offset_t getNextEntryOffset();
    virtual bufsize_t geEntrySize();

protected:
    size_t getEntriesCount(std::vector<ExeNodeWrapper*> &_entries);
    ExeNodeWrapper* getEntryAt(std::vector<ExeNodeWrapper*> &_entries, size_t fieldId);
    
    virtual void clear();
    virtual void addMapping(ExeNodeWrapper *entry) {}
    virtual bool loadNextEntry(size_t entryNum) { return false; } //TODO!
    virtual ExeNodeWrapper* addEntryAt(ExeNodeWrapper *entry, offset_t nextOffset);

    virtual bool isMyEntryType(ExeNodeWrapper *entry); // is it an entry of appropriate type
    
    ExeNodeWrapper* parentNode;
    size_t entryNum;

    std::vector<ExeNodeWrapper*> entries; // children
};

