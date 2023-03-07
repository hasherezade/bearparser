#include "pe/ExportDirWrapper.h"
#include "pe/PEFile.h"

#define INVALID_NAME "<invalid>"
#define INVALID_ID (-1)

/*
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

IMAGE_EXPORT_DIRECTORY* ExportDirWrapper::exportDir()
{
    offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (ptr == NULL) return NULL;

    return (IMAGE_EXPORT_DIRECTORY*) ptr;
}

void ExportDirWrapper::clear()
{
    ExeNodeWrapper::clear();
    this->ordToNameId.clear();
}

size_t ExportDirWrapper::mapNames()
{
    IMAGE_EXPORT_DIRECTORY* exp = exportDir();
    if (exp == NULL) return 0;

    size_t maxNames = exp->NumberOfNames;

    offset_t nameOrdRVA = exp->AddressOfNameOrdinals;
    //uint64_t nameRVA = exp->AddressOfNames;
    size_t i = 0;
    for (i = 0; i < maxNames; i++) {

        WORD* nameOrd = (WORD*) this->m_Exe->getContentAt(nameOrdRVA, Executable::RVA, sizeof(WORD));
        //DWORD* name = (DWORD*) this->m_Exe->getContentAt(nameRVA, Executable::RVA, sizeof(DWORD));
        if (nameOrd == NULL) break;

        this->ordToNameId[*nameOrd] = i;//*name;

        nameOrdRVA += sizeof(WORD);
        //nameRVA += sizeof(DWORD);
    }
    //printf("parsed num: %d\n", this->ordToNameRVA.size());
    return i;
}

bool ExportDirWrapper::wrap()
{
    clear();
    size_t mapNum = mapNames();

    IMAGE_EXPORT_DIRECTORY* exp = exportDir();
    if (exp == NULL) return 0;

    size_t maxFunc = exp->NumberOfFunctions;

    for (size_t i = 0; i < maxFunc; i++) {
        //TODO: build entries...
        ExportEntryWrapper *entry = new ExportEntryWrapper(m_Exe, this, i);
        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        this->entries.push_back(entry);
    }
    return true;
}

bufsize_t ExportDirWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    return sizeof(IMAGE_EXPORT_DIRECTORY);
}

QString ExportDirWrapper::getName()
{
    QString infoName = "Export";
    QString libName = this->getLibraryName();
    if (libName.length() >= 0) {
        infoName += ": "+ libName;
    }
    return infoName;
}

void* ExportDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    IMAGE_EXPORT_DIRECTORY* d = exportDir();
    if (d == NULL) return NULL;

    switch (fId) {
        case CHARACTERISTIC: return &d->Characteristics;
        case TIMESTAMP: return &d->TimeDateStamp;
        case MAJOR_VER: return &d->MajorVersion;
        case MINOR_VER: return &d->MinorVersion;
        case NAME_RVA: return &d->Name;
        case BASE: return &d->Base;
        case FUNCTIONS_NUM: return &d->NumberOfFunctions;
        case NAMES_NUM: return &d->NumberOfNames;
        case FUNCTIONS_RVA: return &d->AddressOfFunctions;
        case FUNC_NAMES_RVA: return &d->AddressOfNames;
        case NAMES_ORDINALS_RVA: return &d->AddressOfNameOrdinals;
    }
    return this->getPtr();
}

QString ExportDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case CHARACTERISTIC: return "Characteristics";
        case TIMESTAMP: {
            PEFile* myPe = dynamic_cast<PEFile*>(this->m_Exe);
            if (myPe && myPe->isReproBuild()) {
                return "ReproChecksum";
            }
            return "TimeDateStamp";
        }
        case MAJOR_VER: return "MajorVersion";
        case MINOR_VER: return "MinorVersion";
        case NAME_RVA: return "Name";
        case BASE: return "Base";
        case FUNCTIONS_NUM: return "NumberOfFunctions";
        case NAMES_NUM: return "NumberOfNames";
        case FUNCTIONS_RVA: return "AddressOfFunctions";
        case FUNC_NAMES_RVA: return "AddressOfNames";
        case NAMES_ORDINALS_RVA: return "AddressOfNameOrdinals";
    }
    return getName();
}

Executable::addr_type ExportDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case NAME_RVA:
        case FUNCTIONS_RVA:
        case FUNC_NAMES_RVA:
        case NAMES_ORDINALS_RVA:
            return Executable::RVA;
    }
    return Executable::NOT_ADDR;
}

char* ExportDirWrapper::_getLibraryName()
{
    bool isOk = false;
    offset_t offset = this->getNumValue(NAME_RVA, &isOk);
    if (!isOk) return NULL;

    Executable::addr_type aT = containsAddrType(NAME_RVA);
    if (aT == Executable::NOT_ADDR) return NULL;

    char *ptr = (char*) m_Exe->getContentAt(offset, aT, 1);
    if (!ptr) return NULL;

    return ptr;
}

QString ExportDirWrapper::getLibraryName()
{
    char *name = this->_getLibraryName();
    if (!name) return name;

    if (pe_util::isStrLonger(name, 100)) {
        return INVALID_NAME;
    }
    return QString(name);
}

//----------------------------------------------------------------------------------------------------
void* ExportEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case FUNCTION_RVA: return getFuncRvaPtr();
        case NAME_RVA: return getFuncNameRvaPtr();
    }
    return getPtr();
}

DWORD* ExportEntryWrapper::getFuncRvaPtr()
{
    if (this->parentDir == NULL) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return NULL;

    uint64_t funcRva = exp->AddressOfFunctions;
    funcRva += (this->entryNum * sizeof(DWORD));

    DWORD *ptr =  (DWORD*) m_Exe->getContentAt(funcRva, Executable::RVA, sizeof(DWORD));
    return ptr;
}

bufsize_t ExportEntryWrapper::getSize()
{
    if (this->parentDir == NULL || parentDir->exportDir() == NULL) {
        return 0;
    }
    return sizeof(DWORD);
}

bool ExportEntryWrapper::isByOrdinal()
{
    if (getFuncName() == NULL) return true;
    return false;
}

QString ExportEntryWrapper::getName()
{
    if (isByOrdinal()) {
        uint32_t val = getOrdinal();
        QString ordStr;
        QTextStream(&ordStr) << "<ord: " << QString::number(val, 16) << ">";
        return ordStr;
    }
    char* name = getFuncName();
    if (name == NULL) return "";
    return QString(name);
}

QString ExportEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case FUNCTION_RVA: return "FuncRva";
        case NAME_RVA: return "FuncNameRva";
    }
    return "";
}

offset_t ExportEntryWrapper::getFuncRva()
{
    DWORD *ptr = this->getFuncRvaPtr();
    if (ptr == NULL) return INVALID_ADDR;
    offset_t addr = static_cast<offset_t>(*ptr);
    return addr;
}

uint32_t ExportEntryWrapper::getOrdinal()
{
    if (this->parentDir == NULL) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return 0;

    uint32_t ordinal = static_cast<uint32_t>(this->entryNum) + exp->Base;
    return ordinal;
}

uint32_t ExportEntryWrapper::getFuncNameId()
{
    if (this->parentDir == NULL) return INVALID_ID;

    WORD ord = static_cast<WORD>(this->entryNum);
    std::map<WORD, DWORD>::iterator found = parentDir->ordToNameId.find(ord);
    if (found == parentDir->ordToNameId.end()) {
        return INVALID_ID;
    }
    return found->second;
}

void* ExportEntryWrapper::getFuncNameRvaPtr()
{
    uint32_t nameId = getFuncNameId();
    if (nameId == INVALID_ID) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return NULL;

    if (nameId >= exp->NumberOfNames) return NULL;

    uint64_t nameAddrRVA = exp->AddressOfNames + (nameId * sizeof(DWORD));
    DWORD* valuePtr = (DWORD*) this->m_Exe->getContentAt(nameAddrRVA, Executable::RVA, sizeof(DWORD));
    return valuePtr;
}

offset_t ExportEntryWrapper::getFuncNameRva()
{
    DWORD* valuePtr = (DWORD*) getFuncNameRvaPtr();
    if (valuePtr == NULL) return INVALID_ADDR;
    DWORD value = (*valuePtr);
    return static_cast<offset_t>(value);
}

char* ExportEntryWrapper::getFuncName()
{
    uint64_t funcRva = getFuncNameRva();
    if (funcRva == INVALID_ADDR) return NULL;

    char* name = (char*) this->m_Exe->getContentAt(funcRva, Executable::RVA, 1);
    if (name == NULL) return NULL;
    //TODO.... verify
    return name;
}

char* ExportEntryWrapper::getForwarder()
{
    if (this->parentDir == NULL) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return NULL;

    DWORD* funcRvaPtr = (DWORD*) this->getFuncRvaPtr();
    if (funcRvaPtr == NULL) return NULL;

    char* strPtr = (char*) m_Exe->getContentAt( (*funcRvaPtr), Executable::RVA, 1);
    if (strPtr == NULL) return NULL;

    uint64_t offset = m_Exe->getOffset((BYTE*) strPtr);
    if (offset == INVALID_ADDR) return NULL;

    size_t maxLen = m_Exe->getRawSize() - offset;
    size_t forwarderNameLen = pe_util::forwarderNameLen(strPtr, maxLen);
    if (forwarderNameLen > 0) {
        return strPtr;
    }
    return NULL;
}

