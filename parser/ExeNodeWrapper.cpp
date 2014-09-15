#include "ExeNodeWrapper.h"

ExeNodeWrapper::ExeNodeWrapper(Executable *exec, ExeNodeWrapper* parent)
    : ExeElementWrapper(exec), parentNode(parent), entryNum(0)
{
    wrap();
}

ExeNodeWrapper::ExeNodeWrapper(Executable *exec, ExeNodeWrapper* parent, size_t entryNumber)
    : ExeElementWrapper(exec), parentNode(parent), entryNum(entryNumber)
{
    wrap();
}

ExeNodeWrapper* ExeNodeWrapper::getEntryAt(size_t fieldId)
{
    return (fieldId < this->entries.size()) ? this->entries[fieldId] : NULL;
}

void ExeNodeWrapper::clear()
{
    size_t entriesCount = this->entries.size();
    for (int i = 0; i < entriesCount; i++) {
        delete this->entries[i];
    }
    this->entries.clear();
}

void* ExeNodeWrapper::getSubfieldPtr(size_t fieldId, size_t subField)
{
    ExeNodeWrapper* entry = this->getEntryAt(fieldId);
    if (!entry) return NULL;
    //---
    return entry->getFieldPtr(subField);
}

bufsize_t ExeNodeWrapper::getSubfieldSize(size_t fieldId, size_t subField)
{
    ExeNodeWrapper* entry = this->getEntryAt(fieldId);
    if (!entry) return 0;
    //---
    return entry->getFieldSize(subField);
}

QString ExeNodeWrapper::getSubfieldName(size_t fieldId, size_t subField)
{
    ExeNodeWrapper* entry = this->getEntryAt(fieldId);
    if (!entry) return "";
    //---
    return entry->getFieldName(subField);
}

bool ExeNodeWrapper::canAddEntry()
{
    offset_t nextOffset = getNextEntryOffset();
    bufsize_t entrySize = geEntrySize();
    if (entrySize == 0) return false;

    bufsize_t paddedSize = entrySize * 2;
    bool haveSpace = this->m_Exe->isAreaEmpty(nextOffset, paddedSize);
    if (DBG_LVL) printf("nextOffset = %llX size = %lX, canAdd: %d\n", nextOffset, entrySize, haveSpace);
    return haveSpace;
}

bool ExeNodeWrapper::isMyEntryType(ExeNodeWrapper *entry)
{
    if (entry == NULL) return false;
    return true; //type cast check in inherited wrappers
}

ExeNodeWrapper* ExeNodeWrapper::getLastEntry() 
{
    size_t lastId = this->getEntriesCount() - 1;
    return this->getEntryAt(lastId);
}

offset_t ExeNodeWrapper::getNextEntryOffset()
{
    ExeNodeWrapper *lastEntry = getLastEntry();
    if (lastEntry == NULL) return INVALID_ADDR;

    offset_t lastOffset = lastEntry->getOffset();
    if (lastOffset == INVALID_ADDR) return INVALID_ADDR;

    bufsize_t entrySize = lastEntry->getSize();
    offset_t nextOffset = lastOffset + entrySize;
    return nextOffset;
}

bufsize_t ExeNodeWrapper::geEntrySize()
{
    ExeNodeWrapper *lastEntry = getLastEntry();
    if (lastEntry == NULL) return 0;

    bufsize_t entrySize = lastEntry->getSize();
    return entrySize;
}

ExeNodeWrapper* ExeNodeWrapper::addEntryAt(ExeNodeWrapper *entry, offset_t nextOffset)
{
    if (canAddEntry() == false) return NULL;

    size_t entryNum = this->getEntriesCount();

    if (nextOffset == INVALID_ADDR) return NULL;
    if (entry == NULL) {
        // if no entry supplied, duplicate the last entry...
        entry = this->getLastEntry();
    }

    if (isMyEntryType(entry) == false) return NULL;
//  if (entrySize != entry->getSize()) return NULL;
    if (m_Exe->pasteBuffer(nextOffset, entry, false) == false) {
        return  NULL;
    } 
    if (loadNextEntry(entryNum) == false) return NULL;
    reloadMapping();
//  printf("ENTRIES NUM  %d\n", this->getEntriesCount());
    return getLastEntry();
}

ExeNodeWrapper* ExeNodeWrapper::addEntry(ExeNodeWrapper *entry)
{
    offset_t offset = getNextEntryOffset();
    return addEntryAt(entry, offset);
}

