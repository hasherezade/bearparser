#include "RelocDirWrapper.h"
#include "PEFile.h"

size_t RelocDirWrapper::EntriesLimit = 10000;

/*
// Based relocation format.

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
    //  WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;


//Based relocation types.

enum reloc_based {
    RELB_ABSOLUTE = 0,
    RELB_HIGH = 1,
    RELB_LOW = 2,
    RELB_HIGHLOW = 3,
    RELB_HIGHADJ = 4,
    RELB_MIPS_JMPADDR = 5,
    RELB_SECTION = 6,
    RELB_REL32 =  7,
    RELB_MIPS_JMPADDR16 = 9,
    RELB_IA64_IMM64 = 9,
    RELB_DIR64 =  10,
    RELB_HIGH3ADJ = 11
};

*/

bool RelocDirWrapper::wrap()
{
    clear();
    parsedSize = 0;
    bufsize_t maxSize = getDirEntrySize();

    for (size_t i = 0; i < RelocDirWrapper::EntriesLimit && parsedSize < maxSize; i++) {
        RelocBlockWrapper* entry = new RelocBlockWrapper(this->m_Exe, this, i);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        bool isOk = false;
        bufsize_t val = (bufsize_t) entry->getNumValue(RelocBlockWrapper::BLOCK_SIZE, &isOk);

        this->parsedSize += val;
        this->entries.push_back(entry);

    }
    return true;
}


IMAGE_BASE_RELOCATION* RelocDirWrapper::reloc()
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(IMAGE_BASE_RELOCATION));
    if (ptr == NULL) return NULL;

    IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION*) ptr;
    return reloc;
}

//----------------

bool RelocBlockWrapper::wrap()
{
    clear();
    parsedSize = 0;

    IMAGE_BASE_RELOCATION* reloc = myReloc();
    if (!reloc) return false;

    size_t maxSize = reloc->SizeOfBlock;
    parsedSize = sizeof(reloc->VirtualAddress) + sizeof(reloc->SizeOfBlock);

    for (size_t i = 0; i < RelocDirWrapper::EntriesLimit && parsedSize < maxSize; i++) {
        RelocEntryWrapper* entry = new RelocEntryWrapper(this->m_Exe, this, i);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        bool isOk = false;
        size_t val = sizeof(WORD);

        this->parsedSize += val;
        this->entries.push_back(entry);
    }
    return true;
}


void* RelocBlockWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;
    IMAGE_BASE_RELOCATION* reloc = this->parentDir->reloc();
    if (!reloc) return NULL;

    offset_t raw = INVALID_ADDR;
    BYTE *ptr = NULL;

    // use my cached:
    if (this->cachedRaw != INVALID_ADDR) {
        ptr = m_Exe->getContentAt(this->cachedRaw, Executable::RAW, sizeof(IMAGE_BASE_RELOCATION));
        return ptr;
    }

    // use previous cached to calculate my cached
    size_t prevNum = this->entryNum - 1;

    RelocBlockWrapper *prevEntry = dynamic_cast<RelocBlockWrapper*> (this->parentDir->getEntryAt(prevNum));
    if (prevEntry) {
        offset_t prevRaw = prevEntry->cachedRaw;

        IMAGE_BASE_RELOCATION* prevReloc = (IMAGE_BASE_RELOCATION*) prevEntry->getPtr();
        raw = prevRaw + prevReloc->SizeOfBlock;

        if (prevRaw != INVALID_ADDR) {
            ptr = m_Exe->getContentAt(raw, Executable::RAW, sizeof(IMAGE_BASE_RELOCATION));

            if (ptr != NULL) {
                this->cachedRaw = raw;
                return ptr;
            }
        }
    }
    // previous cached not avaliable, calculate...
    offset_t firstRaw = this->getOffset(reloc);
    offset_t blockSize = reloc->SizeOfBlock;

    raw = firstRaw;
    ptr = (BYTE*) reloc;

    for ( int i = 0; i < this->entryNum; i++) { //TODO: make caching
        raw += blockSize;

        ptr = m_Exe->getContentAt(raw, Executable::RAW, sizeof(IMAGE_BASE_RELOCATION));
        if (!ptr) return NULL;

        reloc = (IMAGE_BASE_RELOCATION*) ptr;
        blockSize = reloc->SizeOfBlock;
    }

    this->cachedRaw = raw;
    return ptr;
}

bufsize_t RelocBlockWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*) this->getPtr();
    if (!reloc) return 0;

    if (reloc->SizeOfBlock > 0) return reloc->SizeOfBlock;

    return sizeof(IMAGE_BASE_RELOCATION);
}

void* RelocBlockWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*) this->getPtr();
    if (!reloc) return NULL;

    switch (fieldId) {
        case PAGE_VA: return (void*) &reloc->VirtualAddress;
        case BLOCK_SIZE : return (void*) &reloc->SizeOfBlock;
        case ENTRIES_PTR :
        {
            BYTE *blockSizePtr = (BYTE*) &reloc->SizeOfBlock;
            return blockSizePtr + sizeof(DWORD);
        }
    }
    return getPtr();
}

QString RelocBlockWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case BLOCK_SIZE : return "Block Size";
        case PAGE_VA: return "Page RVA";
        case ENTRIES_PTR: return "Entries";
    }
    return getName();
}

Executable::addr_type RelocBlockWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case PAGE_VA:
            return Executable::RVA;
    }
    return Executable::NOT_ADDR;
}

WrappedValue::data_type RelocBlockWrapper::containsDataType(size_t fieldId, size_t subField)
{
    if (fieldId == ENTRIES_PTR){
        return WrappedValue::COMPLEX;
    }
    return WrappedValue::INT;
}

void* RelocBlockWrapper::getEntriesPtr()
{
    void *entriesPtr = getFieldPtr(ENTRIES_PTR);
    size_t entriesSize = getFieldSize(ENTRIES_PTR);

    if (entriesPtr == NULL || entriesSize == 0) return NULL;

    uint32_t entriesOffset = getFieldOffset(ENTRIES_PTR);
    void *ptr = this->m_Exe->getContentAt(entriesOffset, Executable::RAW, sizeof(WORD));

    return ptr;
}

size_t RelocBlockWrapper::maxEntriesNumInBlock()
{
    if (this->cachedMaxNum > 0) return this->cachedMaxNum;

    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*) this->getPtr();
    if (!reloc) return 0;

    bufsize_t entriesSize = getFieldSize(ENTRIES_PTR);
    offset_t entriesOffset = getFieldOffset(ENTRIES_PTR);

    offset_t fileSize = m_Exe->getRawSize();
    if (entriesOffset + entriesSize > fileSize) {
        entriesSize = fileSize - entriesOffset; // truncate to fileSize
    }

    void *ptr = this->m_Exe->getContentAt(entriesOffset, Executable::RAW, entriesSize);

    bufsize_t entriesNum = 0;
    if (ptr) {
        entriesNum = entriesSize / sizeof(WORD); //sizeof(BASE_RELOCATION_ENTRY);
    }
    this->cachedMaxNum = entriesNum;
    return entriesNum;
}
//-------------------------------------------------------------------------------------------------

void* RelocEntryWrapper::getPtr()
{
    if (this->parentDir == NULL) return NULL;

    size_t maxNum = this->parentDir->maxEntriesNumInBlock();
    if (this->entryNum >=  maxNum) return NULL;

    WORD* entriesPtr = (WORD* ) parentDir->getEntriesPtr();
    if (entriesPtr == NULL) return NULL;

    WORD* ptr = &entriesPtr[this->entryNum];
    return ptr;
}

bufsize_t RelocEntryWrapper::getSize()
{
    if (this->parentDir == NULL) return 0;
    return sizeof(WORD);
}

WORD RelocEntryWrapper::getType(WORD relocEntryVal)
{
    pe::BASE_RELOCATION_ENTRY* entry = (pe::BASE_RELOCATION_ENTRY*) &relocEntryVal;
    return entry->Type;
}

WORD RelocEntryWrapper::getDelta(WORD relocEntryVal)
{
    pe::BASE_RELOCATION_ENTRY* entry = (pe::BASE_RELOCATION_ENTRY*) &relocEntryVal;
    return entry->Offset;
}

QString RelocEntryWrapper::translateType(WORD type)
{
    switch (type) {
        case 0 : return "Padding (skipped)";
        case 1 : return "High WORD of 32-bit field";
        case 2 : return "Low  WORD of 32-bit field";
        case 3 : return "32 bit field";
        case 4 : return "HighAdj";
        case 5 : return "MIPS JumpAddr";
        case 6 : case 7 : return "Reserved";
        case 9 : return "MIPS16 JumpAddr";
        case 10 : return "64 bit field";
    }
    return "";
}

offset_t RelocEntryWrapper::deltaToRVA(WORD delta)
{
    if (this->parentDir == NULL) return INVALID_ADDR;

    IMAGE_BASE_RELOCATION* reloc = parentDir->myReloc();
    if (reloc == NULL) return INVALID_ADDR;

    offset_t offset = static_cast<offset_t>(reloc->VirtualAddress + delta);
    return offset;
}

