#include "pe/ExceptionDirWrapper.h"
#include "pe/PEFile.h"

/*
typedef struct _IMAGE_IA64_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} IMAGE_IA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY;
*/

typedef struct _ARM_EXCEPT_RECORD {
    DWORD Start;
    DWORD Xdata;
} ARM_EXCEPT_RECORD;


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

//----------------

void* ExceptionEntryWrapper::getPtr()
{
    if (!this->parentDir) {
        return NULL;
    }
    const size_t entrySize = _getSize();
    void* first = parentDir->getPtr();
    if (!first || !entrySize) {
        return NULL;
    }
    
    uint64_t firstOffset = this->getOffset(first);
    uint64_t myOffset = firstOffset + this->entryNum * entrySize;

    BYTE* ptr = m_Exe->getContentAt(myOffset, Executable::RAW, entrySize);
    return ptr;
}

bufsize_t ExceptionEntryWrapper::_getSize()
{
    if (this->m_Exe) {
        if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
            return sizeof(IMAGE_IA64_RUNTIME_FUNCTION_ENTRY);
        }
        if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
            return 8;
        }
    }
    return 0;  
}

bufsize_t ExceptionEntryWrapper::getSize()
{
    if (!this->parentDir) return 0;
    if (!this->getPtr()) return 0;

    return _getSize();
}

size_t ExceptionEntryWrapper::getFieldsCount()
{
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        return ExceptionBlockFID_Intel::FIELD_COUNTER; 
    }
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        return ExceptionBlockFID_Arm64::ARM_EXCEPT_FIELD_COUNTER;
    }
    return 0;
}

void* ExceptionEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    void *ptr = this->getPtr();
    if (!ptr) return nullptr;
    
    if (this->m_Exe->getArch() == Executable::ARCH_INTEL) {
        IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exc = (IMAGE_IA64_RUNTIME_FUNCTION_ENTRY*) ptr;
        if (!exc) return NULL;

        switch (fieldId) {
            case BEGIN_ADDR : return &exc->BeginAddress;
            case END_ADDR : return &exc->EndAddress;
            case UNWIND_INFO_ADDR : return &exc->UnwindInfoAddress;
        }
    }
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        ARM_EXCEPT_RECORD *rec = (ARM_EXCEPT_RECORD*) ptr;
        if (!rec) return NULL;
        
        switch (fieldId) {
            case ARM_EXCEPT_START : return &rec->Start;
            case ARM_EXCEPT_XDATA : return &rec->Xdata;
        }
    }
    return ptr;
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
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {
        switch (fieldId) {
            case ARM_EXCEPT_START : return "Start";
            case ARM_EXCEPT_XDATA : return "XData";
        }
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
    else if (this->m_Exe->getArch() == Executable::ARCH_ARM && this->m_Exe->getBitMode() == 64) {

        if (fieldId == ARM_EXCEPT_START) return Executable::RVA;
        if (fieldId == ARM_EXCEPT_XDATA) {
            ARM_EXCEPT_RECORD *rec = (ARM_EXCEPT_RECORD*) this->getPtr();
            if (!rec) return Executable::NOT_ADDR;
            
            if (rec->Xdata & ARM_XDATA_FLAG) {
                return Executable::NOT_ADDR;
            }
            return Executable::RVA;
        }
    }
    return Executable::NOT_ADDR;
}
