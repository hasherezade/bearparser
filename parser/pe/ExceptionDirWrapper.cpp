#include "pe/ExceptionDirWrapper.h"
#include "pe/PEFile.h"

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

    const size_t ENTRY_SIZE = sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
    size_t entryId = 0;
    while (parsedSize < maxSize) {
        ExceptionEntryWrapper* entry = new ExceptionEntryWrapper(this->m_Exe, this, entryId++);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        this->parsedSize += ENTRY_SIZE;
        this->entries.push_back(entry);
    }
    Logger::append(Logger::D_INFO,
        "Entries num = %lu, parsedSize = %lX",
        static_cast<unsigned long>(entries.size()),
        static_cast<unsigned long>(parsedSize)
    );
    return true;
}

IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* ExceptionDirWrapper::exceptFunc64()
{
    offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY));
    if (ptr == NULL) return NULL;

    IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exc = (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY*) ptr;
    return exc;
}

//----------------

void* ExceptionEntryWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;
    IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* first =  this->parentDir->exceptFunc64();
    if (!first) return NULL;

    const size_t ENTRY_SIZE = sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);

    uint64_t firstOffset = this->getOffset(first);
    uint64_t myOffset = firstOffset + this->entryNum * ENTRY_SIZE;

    BYTE *ptr = m_Exe->getContentAt(myOffset, Executable::RAW, ENTRY_SIZE);
    return ptr;
}

bufsize_t ExceptionEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    if (this->getPtr() == NULL) return 0;

    return sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
}

void* ExceptionEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exc = (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY*) this->getPtr();
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

