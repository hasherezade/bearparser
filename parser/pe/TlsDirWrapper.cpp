#include "TlsDirWrapper.h"
#include "PEFile.h"

size_t TlsDirWrapper::EntriesLimit = 10000;

bool TlsDirWrapper::wrap()
{
    clear();

    for (size_t i = 0; i < TlsDirWrapper::EntriesLimit; i++) {
        TlsEntryWrapper* entry = new TlsEntryWrapper(this->m_Exe, this, i);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }

        bool isOk = false;
        uint64_t val = entry->getNumValue(TlsEntryWrapper::CALLBACK_ADDR, &isOk);
        if (!isOk || val == 0) {
            delete entry;
            break;
        }
        this->entries.push_back(entry);
    }
    return true;
}

void* TlsDirWrapper::getPtr()
{
    if (m_Exe->getBitMode() == Executable::BITS_32) {
        return tls32();
    }
    return tls64();
}

bufsize_t TlsDirWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    if (m_Exe->getBitMode() == Executable::BITS_32) {
        return sizeof(IMAGE_TLS_DIRECTORY32);
    }
    return sizeof(IMAGE_TLS_DIRECTORY64);
}

void* TlsDirWrapper::getTlsDirPtr()
{
    bufsize_t dirSize = 0;

    if (m_Exe->getBitMode() == Executable::BITS_32) {
        dirSize = sizeof(IMAGE_TLS_DIRECTORY32);
    } else if (m_Exe->getBitMode() == Executable::BITS_64) {
        dirSize = sizeof(IMAGE_TLS_DIRECTORY64);
    }

    offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, dirSize);
    return ptr;
}

IMAGE_TLS_DIRECTORY32* TlsDirWrapper::tls32()
{
    if (m_Exe->getBitMode() != Executable::BITS_32) return NULL;
    return (IMAGE_TLS_DIRECTORY32*) getTlsDirPtr();
}

IMAGE_TLS_DIRECTORY64* TlsDirWrapper::tls64()
{
    if (m_Exe->getBitMode() != Executable::BITS_64) return NULL;
    return (IMAGE_TLS_DIRECTORY64*) getTlsDirPtr();
}

void* TlsDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    IMAGE_TLS_DIRECTORY32* t32 = tls32();
    IMAGE_TLS_DIRECTORY64* t64 = tls64();

    if (t32 == NULL && t64 == NULL) return NULL;

    switch (fId) {
        case START_ADDR : return t32 ? (void*) &t32->StartAddressOfRawData : (void*) &t64->StartAddressOfRawData;
        case END_ADDR : return t32 ? (void*) &t32->EndAddressOfRawData : (void*) &t64->EndAddressOfRawData;
        case INDEX_ADDR : return t32 ? (void*) &t32->AddressOfIndex : (void*) &t64->AddressOfIndex;
        case CALLBACKS_ADDR : return t32 ? (void*) &t32->AddressOfCallBacks : (void*) &t64->AddressOfCallBacks;
        case ZEROF_SIZE : return t32 ? (void*) &t32->SizeOfZeroFill : (void*) &t64->SizeOfZeroFill;
        case CHRARCT : return t32 ? (void*) &t32->Characteristics : (void*) &t64->Characteristics;
    }
    return this->getPtr();
}

QString TlsDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case START_ADDR : return "StartAddressOfRawData";
        case END_ADDR : return "EndAddressOfRawData";
        case INDEX_ADDR : return "AddressOfIndex";
        case CALLBACKS_ADDR : return "AddressOfCallBacks";
        case ZEROF_SIZE : return "SizeOfZeroFill";
        case CHRARCT : return "Characteristics";
    }
    return getName();
}

Executable::addr_type TlsDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case START_ADDR :
        case END_ADDR :
        case INDEX_ADDR :
        case CALLBACKS_ADDR :
            return Executable::VA;
    }
    return Executable::NOT_ADDR;
}

//----------------
void* TlsEntryWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;

    bool isOk = false;
    offset_t firstVA = static_cast<offset_t>(this->parentDir->getNumValue(TlsDirWrapper::CALLBACKS_ADDR, &isOk));
    if (!isOk) return NULL;

    offset_t firstRaw = m_Exe->toRaw(firstVA, Executable::VA);
    if (firstRaw == INVALID_ADDR) return NULL;

    bufsize_t addrSize = this->parentDir->getFieldSize(TlsDirWrapper::CALLBACKS_ADDR);
    offset_t myRaw = firstRaw + (addrSize * this->entryNum);
    BYTE *ptr  = m_Exe->getContentAt(myRaw, Executable::RAW, addrSize);
    return ptr;
}

bufsize_t TlsEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    bufsize_t addrSize = this->parentDir->getFieldSize(TlsDirWrapper::CALLBACKS_ADDR);
    return addrSize;
}
