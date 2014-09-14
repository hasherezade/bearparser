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
    size_t entriesCount = this->entries.size();
    if (entriesCount == 0) {
        if (DBG_LVL) printf("Cannot add enty after the existing entries: no entries at all...\n");
        return false; //do not have any entiries
    }
    ExeNodeWrapper *lastEntry = this->getEntryAt(entriesCount - 1);
    offset_t lastOffset = lastEntry->getOffset();
    bufsize_t entrySize = lastEntry->getSize();

    offset_t nextOffset = lastOffset + entrySize;
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

ExeNodeWrapper* ExeNodeWrapper::addEntry(ExeNodeWrapper *entry)
{
    if (canAddEntry() == false) return NULL;

    ExeNodeWrapper *lastEntry = this->getEntryAt(this->entries.size() - 1);
    if (lastEntry == NULL) return NULL;

    offset_t lastOffset = lastEntry->getOffset();
    bufsize_t entrySize = lastEntry->getSize();

    offset_t nextOffset = lastOffset + entrySize;

    if (entry == NULL) {
        // if no entry supplied, duplicate the last entry...
        entry = lastEntry;
    }
    if (isMyEntryType(entry) == false) return NULL;
    if (entrySize != entry->getSize()) return NULL;

    if (m_Exe->pasteBuffer(nextOffset, entry, false) == false) {
        return  NULL;
    }
    this->clear();
    this->wrap();
    return getLastEntry();
}

