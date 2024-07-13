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
    bufsize_t maxSize = getDirEntrySize(true);
    if (maxSize == 0) return false; // nothing to parse

    if (!getPtr()) return false;

    size_t entrySize = 0;
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        entrySize = sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
    }
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        entrySize = 8;
    }
    size_t entryId = 0;
    while (parsedSize < maxSize) {
        ExceptionEntryWrapper* entry = new ExceptionEntryWrapper(this->m_Exe, this, entryId++);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        this->parsedSize += entrySize;
        this->entries.push_back(entry);
    }
    Logger::append(Logger::D_INFO,
        "Entries num = %lu, parsedSize = %lX",
        static_cast<unsigned long>(entries.size()),
        static_cast<unsigned long>(parsedSize)
    );
    return true;
}

void* ExceptionDirWrapper::getPtr()
{
    size_t entrySize = 0;
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        entrySize = sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
    }
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        entrySize = sizeof(uint64_t);
    }
    const offset_t rva = getDirEntryAddress();
    BYTE* first = m_Exe->getContentAt(rva, Executable::RVA, entrySize);
    if (!first || !entrySize) {
        return NULL;
    }
    return first;
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
    if (!this->parentDir) {
        return NULL;
    }
    size_t entrySize = 0;
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        entrySize = sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
    }
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        entrySize = 8;
    }
    void* first = parentDir->getPtr();
    if (!first || !entrySize) {
        return NULL;
    }
    
    uint64_t firstOffset = this->getOffset(first);
    uint64_t myOffset = firstOffset + this->entryNum * entrySize;

    BYTE* ptr = m_Exe->getContentAt(myOffset, Executable::RAW, entrySize);
    return ptr;
}

bufsize_t ExceptionEntryWrapper::getSize()
{
    if (!this->parentDir) return 0;
    if (!this->getPtr()) return 0;
    
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        return sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
    }
    if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        return 8;
    }
    return 0;
}

size_t ExceptionEntryWrapper::getFieldsCount()
{
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        return FIELD_COUNTER; 
    }
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        return 1;
    }
    return 0;
}

void* ExceptionEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exc = (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY*) this->getPtr();
        if (!exc) return NULL;

        switch (fieldId) {
            case BEGIN_ADDR : return &exc->BeginAddress;
            case END_ADDR : return &exc->EndAddress;
            case UNWIND_INFO_ADDR : return &exc->UnwindInfoAddress;
        }
    }
    if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        switch (fieldId) {
            case BEGIN_ADDR : this->getPtr();
        }
    }
    return getPtr();
}

QString ExceptionEntryWrapper::getFieldName(size_t fieldId)
{
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        switch (fieldId) {
            case BEGIN_ADDR : return "BeginAddress";
            case END_ADDR : return "EndAddress";
            case UNWIND_INFO_ADDR : return "UnwindInfoAddress";
        }
        return "";
    }
    if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        if (fieldId == BEGIN_ADDR) return "Record";
    }
    return getName();
}

Executable::addr_type ExceptionEntryWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        switch (fieldId) {
            case BEGIN_ADDR :
            case END_ADDR :
            case UNWIND_INFO_ADDR :
                return Executable::RVA;
        }
    }
    return Executable::NOT_ADDR;
}

