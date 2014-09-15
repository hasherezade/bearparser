#include "ImportDirWrapper.h"
#include "PEFile.h"

using namespace pe;
using namespace imports_util;

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

offset_t ImportedFuncWrapper::getFieldRVA(ImportEntryWrapper::FieldID fId)
{
    if (!parentNode) return 0;
    bool is32 = isBit32();

    bool isOk;
    uint64_t thunkRva = parentNode->getNumValue(fId, &isOk);
    if (!isOk) return 0; //TODO

    if (is32) thunkRva = (int32_t)(thunkRva);
    if (thunkRva == 0 ||  thunkRva == (-1)) return 0; //TODO

    size_t thunkValSize = this->getThunkValSize();
    offset_t offset = this->entryNum * thunkValSize;

    offset_t fieldRVA = thunkRva + offset;
    return fieldRVA;
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

    size_t thunkValSize = this->getThunkValSize();
    offset_t offset = static_cast<offset_t>(this->entryNum) * thunkValSize;

    offset_t thunkAddr = m_Exe->toRaw(thunkRva + offset, Executable::RVA);
    void* thunkPtr = m_Exe->getContentAt(thunkAddr, thunkValSize);
    return thunkPtr;
}

uint64_t ImportedFuncWrapper::getThunkValue()
{
    bool isOk = false;
    bool is64 = (m_Exe->getBitMode() == Executable::BITS_64) ? true : false;

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

    void *p = getValuePtr(ImportEntryWrapper::ORIG_FIRST_THUNK);
    if (!p) p = getValuePtr(ImportEntryWrapper::FIRST_THUNK);
    if (!p) return NULL;

    if (isBit64()) {
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
    return getAddrSize();
}

void* ImportedFuncWrapper::getFieldPtr(size_t fId, size_t subField)
{
    bool is64 = isBit64();
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
    bufsize_t entrySize = (isBit64()) ? sizeof(uint64_t) : sizeof(uint32_t);
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


 bool ImportEntryWrapper::loadNextEntry(size_t entryNum)
 {
    ImportedFuncWrapper* func = new ImportedFuncWrapper(m_PE, this, entryNum);
    offset_t thunk = func->getThunkValue();

    if (thunk == 0 || thunk == INVALID_ADDR) {
        delete func;
        func = NULL;
        return false;
    } else {
        entries.push_back(func);
        addMapping(func);
    }
    return true;
 }


void* ImportEntryWrapper::getPtr()
{
    if (m_PE == NULL) return NULL;
    IMAGE_DATA_DIRECTORY *d = m_PE->getDataDirectory();
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

    offset_t nameRVA = desc->Name;
    offset_t nAddr = m_Exe->toRaw(nameRVA, Executable::RVA);
    if (nAddr == INVALID_ADDR) return NULL;

    //TODO: reimplement it:
    char *name = (char*) m_Exe->getContentAt(nAddr, sizeof(char));
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

bool ImportDirWrapper::loadNextEntry(size_t cntr)
{
    ImportEntryWrapper* imp = new ImportEntryWrapper(m_PE, this, cntr);
    if (!imp || !imp->getPtr()) {
        delete imp;
        return false;
    }
    bool isOk = false;
    uint64_t thunk = imp->getNumValue(ImportEntryWrapper::FIRST_THUNK, &isOk);
    if (!isOk) {
        delete imp;
        return false;
    }
    uint64_t oThunk = imp->getNumValue(ImportEntryWrapper::ORIG_FIRST_THUNK, &isOk);
    if (!isOk) {
        delete imp;
        return false;
    }
    if (!thunk && !oThunk) {
        delete imp;
        return false;
    }
    entries.push_back(imp);
    return true;
}

bufsize_t ImportDirWrapper::getSize()
{
    size_t fields = getFieldsCount() + 1; //fields + terminating field
    return static_cast<bufsize_t>(fields) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

