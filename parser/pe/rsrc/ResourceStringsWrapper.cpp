#include "ResourceStringsWrapper.h"

void* ResString::getPtr()
{
    return this->sizePtr;
}

bufsize_t ResString::getSize() {
    WORD* len = this->sizePtr;
    if (len == NULL) return 0;
    return (*len) * sizeof(WORD) + sizeof(WORD);
}

QString ResString::getName()
{
    return getQString();
}

/* specific field boundaries */
void* ResString::getFieldPtr(size_t fId, size_t subField)
{
    switch (fId) {
        case STR_LEN: return this->sizePtr;
        case WSTRING:
        {
            bufsize_t size = (sizePtr == NULL) ? 0 : static_cast<bufsize_t>(*sizePtr);
            WORD *content = (WORD*) this->m_Exe->getContentAt(offset,Executable::RAW, size);
            return content;
        }
    }
    return this->getPtr();
}

QString ResString::getFieldName(size_t fId)
{
    switch (fId) {
        case STR_LEN: return "Length";
        case WSTRING: return "WString";
    }
    return "";
}

bufsize_t ResString::getFieldSize(size_t fId, size_t subField)
{
    switch (fId) {
        case STR_LEN: return sizeof(WORD);
        case WSTRING:
        {
            WORD* len = this->sizePtr;
            if (len == NULL) return 0;
            return (*len) * sizeof(WORD);
        }
    }
    return 0;
}
//------------------------------------------------------
size_t ResourceStringsWrapper::EntriesLimit = 10000;

bool ResourceStringsWrapper::wrap()
{
    clear();
    this->parsedSize = 0;

    BYTE *c = static_cast<BYTE*>(this->getPtr());
    if (!c) {
        return false;
    }
    size_t maxSize = this->getSize();
    //printf("maxSize = %x\n", maxSize);
    offset_t startRaw = getContentRaw();
    offset_t cRaw = startRaw;

    for (size_t i = 0; i < ResourceStringsWrapper::EntriesLimit && parsedSize < maxSize; i++) {

        WORD* stringSize = (WORD*) this->getContentAt(cRaw, Executable::RAW, sizeof(WORD));
        if (stringSize == NULL){
            printf("Cannot fetch the string size!\n");
            break;
        }
        this->parsedSize += sizeof(WORD);
        cRaw += sizeof(WORD);

        size_t wStrSize = (*stringSize);
        if (wStrSize == 0) {
            continue;
        }
        bufsize_t totalStrSize = wStrSize * sizeof(WORD);

        WORD* uStringPtr = (WORD*) this->getContentAt(cRaw, Executable::RAW, totalStrSize);
        if (uStringPtr == NULL) break;

        Executable *exe = this->myLeaf->getExe();
        ResString *rStr = new ResString(uStringPtr, stringSize, cRaw, exe);
        this->entries.push_back(rStr);

        this->parsedSize += totalStrSize;
        cRaw += totalStrSize;
    }
    return true;
}

QString ResourceStringsWrapper::getFieldName(size_t fId)
{
    return "ResourceString";
}

void* ResourceStringsWrapper::getFieldPtr(size_t fId, size_t subField)
{
    if (fId >= this->entries.size()) return NULL;
    return this->entries[fId]->getFieldPtr(subField);
}

bufsize_t ResourceStringsWrapper::getFieldSize(size_t fId, size_t subField)
{
    if (fId >= this->entries.size()) return 0;
    return this->entries[fId]->getFieldSize(subField);
}

