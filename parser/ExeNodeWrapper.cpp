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

