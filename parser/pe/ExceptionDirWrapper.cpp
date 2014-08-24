#include "ExceptionDirWrapper.h"
#include "PEFile.h"

uint64_t ExceptionDirWrapper::EntriesLimit = 10000;

/*
typedef struct _IMAGE_IA64_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} IMAGE_IA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY;
*/

bool ExceptionDirWrapper::wrap()
{
    clear();
    parsedSize = 0;
    bufsize_t maxSize = getDirEntrySize();
    if (maxSize == 0) return false; // nothing to parse

    if (!exceptFunc64()) return false;

    //printf("maxSize = %x\n", maxSize);
    const size_t ENTRY_SIZE = sizeof(pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);

    for (int i = 0; i < ExceptionDirWrapper::EntriesLimit && parsedSize < maxSize; i++) {
        ExceptionEntryWrapper* entry = new ExceptionEntryWrapper(this->m_Exe, this, i);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        this->parsedSize += ENTRY_SIZE;
        this->entries.push_back(entry);

        /*printf("pageVA = %llx size = %llx\n",
            entry->getNumValue(ExceptionEntryWrapper::PAGE_VA, &isOk),
            entry->getNumValue(ExceptionEntryWrapper::BLOCK_SIZE, &isOk)
        );*/

    }
    //printf("entries num = %d, parsedSize = %x\n", entries.size(), parsedSize);
    return true;
}

pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* ExceptionDirWrapper::exceptFunc64()
{
    offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY));
    if (ptr == NULL) return NULL;

    pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exc = (pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY*) ptr;
    return exc;
}

//----------------

void* ExceptionEntryWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;
    pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* first =  this->parentDir->exceptFunc64();
    if (!first) return NULL;

    const size_t ENTRY_SIZE = sizeof(pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);

    uint64_t firstOffset = this->getOffset(first);
    uint64_t myOffset = firstOffset + this->entryNum * ENTRY_SIZE;

    BYTE *ptr = m_Exe->getContentAt(myOffset, Executable::RAW, ENTRY_SIZE);
    return ptr;
}

bufsize_t ExceptionEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    if (this->getPtr() == NULL) return 0;

    return sizeof(pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
}

void* ExceptionEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exc = (pe::IMAGE_IA64_RUNTIME_FUNCTION_ENTRY*) this->getPtr();
    if (!exc) return NULL;

    switch (fieldId) {
        case BEGIN_ADDR : return &exc->BeginAddress;
        case END_ADDR : return &exc->EndAddress;
        case UNWIND_INFO_ADDR : return &exc->UnwindInfoAddress;
    }
    return getPtr();
}

QString ExceptionEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case BEGIN_ADDR : return "BeginAddress";
        case END_ADDR : return "EndAddress";
        case UNWIND_INFO_ADDR : return "UnwindInfoAddress";
    }
    return getName();
}

Executable::addr_type ExceptionEntryWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
    case BEGIN_ADDR :
    case END_ADDR :
    case UNWIND_INFO_ADDR :
            return Executable::RVA;
    }
    return Executable::NOT_ADDR;
}

