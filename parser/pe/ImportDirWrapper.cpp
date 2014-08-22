#include "ImportDirWrapper.h"
#include "PEFile.h"

using namespace pe;

inline uint64_t getUpperLimit(Executable *pe, void* fieldPtr)
{
    if (!pe || ! fieldPtr) return 0;

    int64_t nameOffset = (uint64_t)fieldPtr - (uint64_t)(pe->getContent());
    if (nameOffset < 0) return 0;

    int64_t upperLimit = pe->getRawSize() - nameOffset;
    if (upperLimit < 0) return 0;
    return upperLimit;
}

inline bool isNameValid(Executable *pe, char* myName)
{
    if (!myName) return false; // do not parse, invalid entry

    uint64_t upperLimit = getUpperLimit(pe, myName);
    if (upperLimit == 0) return false;

    bool isInvalid = pe_util::hasNonPrintable(myName, upperLimit);
    if (isInvalid) return false;
    if (pe_util::noWhiteCount(myName) == 0) return false;

    return true;
}
//----------------------------------

void* ImportedFuncWrapper::getPtr()
{
    void *ptr = getValuePtr(ImportEntryWrapper::ORIG_FIRST_THUNK);
    if (!ptr) ptr = getValuePtr(ImportEntryWrapper::FIRST_THUNK);
    return ptr;
}

IMAGE_IMPORT_BY_NAME* ImportedFuncWrapper::getImportByNamePtr()
{
    bool isOk = false;
    uint64_t offset = this->getNumValue(ImportedFuncWrapper::ORIG_THUNK, &isOk);
    if (!isOk || offset == INVALID_ADDR) {
        offset = this->getNumValue(ImportedFuncWrapper::THUNK, &isOk);
    }
    if (!isOk) return NULL;
    BYTE *ptr = this->m_Exe->getContentAt(offset, Executable::RVA, sizeof(IMAGE_IMPORT_BY_NAME));
    return (IMAGE_IMPORT_BY_NAME*) ptr;
}

uint64_t ImportedFuncWrapper::getFieldRVA(ImportEntryWrapper::FieldID fId)
{
    if (!parentNode) return 0;
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;

    bool isOk;
    uint64_t thunkRva = parentNode->getNumValue(fId, &isOk);
    if (!isOk) return 0; //TODO

    if (!is64) thunkRva = (int32_t)(thunkRva);
    if (thunkRva == 0 ||  thunkRva == (-1)) return 0; //TODO

    uint32_t thunkValSize = (is64) ? sizeof(uint64_t) : sizeof(uint32_t);
    uint64_t offset = this->entryNum * thunkValSize;

    return thunkRva + offset;
}

void* ImportedFuncWrapper::getValuePtr(ImportEntryWrapper::FieldID fId)
{
    if (!parentNode) return NULL;
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;

    bool isOk;
    uint64_t thunkRva = parentNode->getNumValue(fId, &isOk);
    if (!isOk) {
        //printf("Failed getting value!\n");
        return NULL;
    }
    if (!is64) thunkRva = (int32_t)(thunkRva);
    if (thunkRva == 0 || thunkRva == -1) return NULL;

    size_t thunkValSize = (is64) ? sizeof(uint64_t) : sizeof(uint32_t);
    offset_t offset = static_cast<offset_t>(this->entryNum) * thunkValSize;

    void* thunkPtr = NULL;
    BYTE *content =  m_Exe->getContent();
    offset_t fileSize = m_Exe->getRawSize();
    if (!content) return NULL;

    try {
        offset_t thunkAddr = 0;
        thunkAddr = m_Exe->rvaToFileAddr(thunkRva + offset);
        if (thunkAddr + thunkValSize > fileSize) {
            //printf("FuncWrapper: Pointer out of File boundaries!\n");
            return NULL;
        }
        thunkPtr = (void*) &content[thunkAddr];
    } catch (CustomException e) {
        return NULL;
    }
    return thunkPtr;
}

void* ImportedFuncWrapper::getDataPtr(ImportEntryWrapper::FieldID fId)
{
    void* thunkPtr = getValuePtr(fId);
    if (!thunkPtr) return NULL;

    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;
    uint64_t thunkValVA = 0; //TODO
    if (is64) {
        uint64_t *ptr = (uint64_t*) thunkPtr;
        thunkValVA = (*ptr);
    } else {
        uint32_t *ptr = (uint32_t*) thunkPtr;
        thunkValVA = (*ptr);
    }
    if (thunkValVA == 0 || thunkValVA == (-1) ) return NULL;
    //---
    size_t entrySize = (is64) ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    // convert VA to RAW:
    BYTE *content =  m_Exe->getContent();
    uint64_t cSize = m_Exe->getRawSize();
    if (!content || cSize == 0) return NULL;

    void *entryPtr = NULL;
    try {
        uint32_t entryAddr = 0;
        thunkValVA = m_Exe->VaToRva(thunkValVA, false);
        entryAddr = m_Exe->rvaToFileAddr(thunkValVA);

        if (entryAddr + entrySize > cSize) return NULL;
        entryPtr = (void*) &content[entryAddr];
    } catch (CustomException e) {
        return NULL;
    }
    return entryPtr;
}

uint64_t ImportedFuncWrapper::getThunkValue()
{
    bool isOk = false;
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;

    uint64_t ordinal = 0;
    void* thunkPtr = getPtr();
    if (!thunkPtr) return 0;

    if (is64) {
        uint64_t* ptr =  (uint64_t*) thunkPtr;
        ordinal = *ptr;
        if (ordinal & ORDINAL_FLAG64) ordinal ^= ORDINAL_FLAG64;

    } else {
        uint32_t* ptr =  (uint32_t*) thunkPtr;
        ordinal = *ptr;
        if (uint32_t(ordinal) & ORDINAL_FLAG32) ordinal ^= ORDINAL_FLAG32;
    }

    return ordinal;
}

bool ImportedFuncWrapper::isByOrdinal()
{
    bool isOk = false;
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;

    void *p = getValuePtr(ImportEntryWrapper::ORIG_FIRST_THUNK);
    if (!p) p = getValuePtr(ImportEntryWrapper::FIRST_THUNK);
    if (!p) return NULL;

    if (is64) {
        uint64_t* ptr =  (uint64_t*) p;
        if ((*ptr) & ORDINAL_FLAG64) return true;

    } else {
        uint32_t* ptr =  (uint32_t*) p;
        if ((*ptr) & ORDINAL_FLAG32) return true;
    }
    return false;
}


char* ImportedFuncWrapper::getFunctionName()
{
    if (isByOrdinal()) return NULL;

    IMAGE_IMPORT_BY_NAME* dataPtr = this->getImportByNamePtr();
    if (!dataPtr) return NULL;
    char *name = (char*) dataPtr->Name;
    return name;
}

bufsize_t ImportedFuncWrapper::getSize()
{
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;
    uint32_t entrySize = (is64) ? sizeof(uint64_t) : sizeof(uint32_t);
    return entrySize;
}

void* ImportedFuncWrapper::getFieldPtr(size_t fId, size_t subField)
{
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;
    void *entryPtr = this->getPtr();
    IMAGE_THUNK_DATA32* en32 = is64 ? NULL : (IMAGE_THUNK_DATA32*) entryPtr;
    IMAGE_THUNK_DATA64* en64 = is64 ? (IMAGE_THUNK_DATA64*) entryPtr : NULL;

    switch (fId) {
        case ORIG_THUNK: return (void*) getValuePtr(ImportEntryWrapper::ORIG_FIRST_THUNK);
        case THUNK: return (void*) getValuePtr(ImportEntryWrapper::FIRST_THUNK);
        case FORWARDER: return (void*) getValuePtr(ImportEntryWrapper::FORWARDER);
        case HINT :
        {
            if (isByOrdinal()) return NULL;
            IMAGE_IMPORT_BY_NAME* dataPtr = this->getImportByNamePtr();
            return (void*) &dataPtr->Hint;
        }
    };
    return entryPtr;
}

bufsize_t ImportedFuncWrapper::getFieldSize(size_t fieldId, size_t subField)
{
    if (fieldId == HINT) return sizeof (WORD);
    bool is64 = (m_Exe->getBitMode() == 64) ? true : false;
    uint32_t entrySize = (is64) ? sizeof(uint64_t) : sizeof(uint32_t);
    return entrySize;
}

QString ImportedFuncWrapper::getFieldName(size_t fId)
{
    switch (fId) {
        case ORIG_THUNK: return "Original Thunk";
        case THUNK: return "Thunk";
        case FORWARDER: return "Forwarder";
        case HINT : return "Hint";
    };
    return "";
}

Executable::addr_type ImportedFuncWrapper::containsAddrType(size_t fId, size_t subField)
{
    if (this->isByOrdinal()) {
        return Executable::NOT_ADDR;
    }
    switch (fId) {
        case ORIG_THUNK:
        case THUNK:
            return Executable::RVA;
    }
    return Executable::NOT_ADDR;
}
//-------------------------------------------------------------------------------

bool ImportEntryWrapper::isValid()
{
    char *libName = this->getLibraryName();
    bool isValid = isNameValid(m_Exe, libName);
    return isValid;
}

bool ImportEntryWrapper::wrap()
{
    clear();
    thunkToFuncMap.clear();

    ImportedFuncWrapper* func = NULL;
    const uint64_t LIMIT = ImportEntryWrapper::EntriesLimit;
    if (!isValid()) {
        return false;
    }
    uint64_t cntr = 0;
    if (this->getPtr() == NULL) {
        return false;
    }
    for (cntr = 0; cntr < LIMIT; cntr++) {
        ImportedFuncWrapper* func = new ImportedFuncWrapper(m_Exe, this, cntr);
        offset_t thunk = func->getThunkValue();
        //printf( "%s\n", func->getName().c_str());
        //printf ("Thunk = %llx\n", thunk);
        if (thunk == 0 || thunk == INVALID_ADDR) {
            delete func;
            func = NULL;
            break;
        } else {
            entries.push_back(func);
            addFuncMapping(func);
        }
    }
    //printf("Entries: %d\n", entries.size());
    return true;
}

void* ImportEntryWrapper::getPtr()
{
    PEFile *pe = dynamic_cast<PEFile*> (this->m_Exe);
    if (pe == NULL) return NULL;

    IMAGE_DATA_DIRECTORY *d = pe->getDataDirectory();
    if (!d) return NULL;

    offset_t importRva = static_cast<offset_t>(d[pe::DIR_IMPORT].VirtualAddress);
    if (importRva == 0) return NULL;

    offset_t descAddr = this->m_Exe->toRaw(importRva, Executable::RVA);
    if (descAddr == INVALID_ADDR) {
        return NULL; // address invalid
    }
    BYTE *dirPtr = this->m_Exe->getContentAt(descAddr, Executable::RAW, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (dirPtr == NULL) return NULL; // address invalid

    offset_t entryOffset = descAddr + (this->entryNum * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    BYTE *content =  this->m_Exe->getContentAt(entryOffset, Executable::RAW, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (!content) return NULL;
    return (void*) content;
}

bufsize_t ImportEntryWrapper::getSize()
{
    return sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

QString ImportEntryWrapper::getName()
{
    char *name = getLibraryName();
    if (!name) return "";
    return name;
}

bool ImportEntryWrapper::isBound()
{
    void *ptr = this->getPtr();
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*) ptr;
    if (!desc) return false;

    if (desc->TimeDateStamp == (-1)) return true;
    return false;
}

void* ImportEntryWrapper::getFieldPtr(size_t fId, size_t subField)
{
    void *ptr = this->getPtr();
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*) ptr;
    if (!desc) return NULL;

    switch (fId) {
        case ORIG_FIRST_THUNK: return (void*) &desc->OriginalFirstThunk;
        case TIMESTAMP: return (void*) &desc->TimeDateStamp;
        case FORWARDER: return (void*) &desc->ForwarderChain;
        case NAME: return (void*) &desc->Name;
        case FIRST_THUNK: return (void*) &desc->FirstThunk;
    }
    return desc;
}

QString ImportEntryWrapper::getFieldName(size_t fId)
{
    switch (fId) {
        case ORIG_FIRST_THUNK: return "OriginalFirstThunk";
        case TIMESTAMP: return "TimeDateStamp";
        case FORWARDER: return "Forwarder";
        case NAME: return "NameRVA";
        case FIRST_THUNK: return "FirstThunk";
    }
    return this->getName();
}

Executable::addr_type ImportEntryWrapper::containsAddrType(size_t fId, size_t subField)
{
    switch (fId) {
        case ORIG_FIRST_THUNK:
        case NAME:
        case FIRST_THUNK:
                return Executable::RVA;
    }
    return Executable::NOT_ADDR;
}

char* ImportEntryWrapper::getLibraryName()
{
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*) getPtr();
    if (!desc) {
        return NULL;
    }
    offset_t nAddr = 0;
    offset_t nameRVA = desc->Name;
    try {
        nAddr = m_Exe->rvaToFileAddr(nameRVA);
    } catch (CustomException e) {

        return NULL;
    }
    if (nAddr >= m_Exe->getRawSize()) return NULL;

    BYTE *content =  m_Exe->getContent();
    if (!content) return NULL;

    char *name = (char*) &content[nAddr];
    offset_t peSize = m_Exe->getRawSize();

    uint64_t upperLimit = getUpperLimit(m_Exe, name);
    uint32_t HARD_LIMIT = ImportEntryWrapper::NameLenLimit;
    int32_t limit = (uint32_t) upperLimit < HARD_LIMIT ? upperLimit : HARD_LIMIT;

    if (pe_util::isStrLonger(name, limit)) {
        if (upperLimit < HARD_LIMIT) {
            return name; // Name at the end of File. FileBuffer secures it with appended \0
        }
        return NULL;
    }
    return name;
}

//---------------------------------

pe::IMAGE_DATA_DIRECTORY* ImportDirWrapper::getDataDirectory()
{
    PEFile *pe = dynamic_cast<PEFile*> (this->m_Exe);
    if (pe == NULL) return NULL;

    IMAGE_DATA_DIRECTORY *d = pe->getDataDirectory();
    return d;
}

pe::IMAGE_IMPORT_DESCRIPTOR* ImportDirWrapper::firstDescriptor()
{
    IMAGE_DATA_DIRECTORY *d = getDataDirectory();
    if (!d) return NULL;

    uint32_t importRva = d[pe::DIR_IMPORT].VirtualAddress;
    if (importRva == 0) return NULL;

    uint64_t descAddr = this->m_Exe->toRaw(importRva, Executable::RVA);
    if (descAddr == INVALID_ADDR) return NULL; // address invalid

    BYTE *dirPtr = this->m_Exe->getContentAt(descAddr, Executable::RAW, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (dirPtr == NULL) return NULL; // address invalid
    return (pe::IMAGE_IMPORT_DESCRIPTOR*) dirPtr;
}

bool ImportDirWrapper::wrap()
{
    clear();
    thunkToLibMap.clear();

    uint64_t cntr = 0;
    if (!m_Exe || !getDataDirectory()) {
        if (this->importsCount == cntr) return false;
        this->importsCount = cntr;
        return true;
    }

    const uint64_t LIMIT = ImportDirWrapper::EntriesLimit;//(-1);
    ImportEntryWrapper* imp = NULL;
    bool isNext = false;

    for (cntr = 0; cntr < LIMIT; cntr++) {
        isNext = false;

        imp = new ImportEntryWrapper(m_Exe, this, cntr);
        if (!imp || !imp->getPtr()) {
            break;
        }

        bool isOk = false;
        uint64_t thunk = imp->getNumValue(ImportEntryWrapper::FIRST_THUNK, &isOk);
        if (!isOk) {
            break;
        }

        uint64_t oThunk = imp->getNumValue(ImportEntryWrapper::ORIG_FIRST_THUNK, &isOk);
        if (!isOk) {
            break;
        }

        if (!thunk && !oThunk) {
            break;
        }
        entries.push_back(imp);
        isNext = true;
    }
    if (!isNext) {
        delete imp;

    }
    if (this->importsCount == cntr) return false;
    this->importsCount = cntr;
    return true;
}

bufsize_t ImportDirWrapper::getSize()
{
    size_t fields = getFieldsCount() + 1; //fields + terminating field
    return static_cast<bufsize_t>(fields) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

