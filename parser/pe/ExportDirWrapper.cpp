#include "ExportDirWrapper.h"
#include "PEFile.h"

#define INVALID_NAME "<invalid>"
#define INVALID_ID (-1)

using namespace pe;

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

pe::IMAGE_EXPORT_DIRECTORY* ExportDirWrapper::exportDir()
{
    IMAGE_DATA_DIRECTORY *d = getDataDirectory(m_Exe);
    if (!d) return NULL;

    offset_t rva = getDirEntryAddress();
    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(pe::IMAGE_EXPORT_DIRECTORY));
    if (ptr == NULL) return NULL;

    return (pe::IMAGE_EXPORT_DIRECTORY*) ptr;
}

void ExportDirWrapper::clear()
{
    ExeNodeWrapper::clear();
    this->ordToNameId.clear();
}

size_t ExportDirWrapper::mapNames()
{
    pe::IMAGE_EXPORT_DIRECTORY* exp = exportDir();
    if (exp == NULL) return 0;

    size_t maxNames = exp->NumberOfNames;

    uint64_t nameOrdRVA = exp->AddressOfNameOrdinals;
    //uint64_t nameRVA = exp->AddressOfNames;
    int i = 0;
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

    pe::IMAGE_EXPORT_DIRECTORY* exp = exportDir();
    if (exp == NULL) return 0;

    size_t maxFunc = exp->NumberOfFunctions;

    for (int i = 0; i < maxFunc; i++) {
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
    return sizeof(pe::IMAGE_EXPORT_DIRECTORY);
}

QString ExportDirWrapper::getName()
{
    QString infoName = "Export";
    char *name = this->getLibraryName();
    if (!name) return infoName;

    if (pe_util::isStrLonger(name, 100)) {
        return INVALID_NAME;
    }
    infoName += ": "+ QString(name);
    return infoName;
}

void* ExportDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::IMAGE_EXPORT_DIRECTORY* d = exportDir();
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
        case TIMESTAMP: return "TimeDateStamp";
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

char* ExportDirWrapper::getLibraryName()
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

//----------------------------------------------------------------------------------------------------
void* ExportEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case FUNCTION_RVA: return getFuncRvaPtr();
        case NAME_RVA: return getFuncNameRvaPtr();
    }
    return getPtr();
}

void* ExportEntryWrapper::getFuncRvaPtr()
{
    if (this->parentDir == NULL) return NULL;
    pe::IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return NULL;

    uint64_t funcRva = exp->AddressOfFunctions;
    funcRva += (this->entryNum * sizeof(DWORD));

    BYTE *ptr =  m_Exe->getContentAt(funcRva, Executable::RVA, sizeof(DWORD));
    return ptr;
}

bufsize_t ExportEntryWrapper::getSize()
{
    if (this->parentDir == NULL || parentDir->exportDir() == NULL) {
        return 0;
    }
    return sizeof(DWORD);
}

QString ExportEntryWrapper::getName()
{
    char *entryName = getFuncName();

    if (entryName == NULL) {
        uint64_t val = getOrdinal();
        static char buf[0xFF];
        snprintf(buf, 0xFF, "<ord: %llX>", val);
        entryName = buf;
    }

    QString name = entryName;
    char *forwarder = getForwarder();
    if ( forwarder != NULL) {
        name += " -> " + QString(forwarder);
    }

    return name;
}

QString ExportEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case FUNCTION_RVA: return "FuncRva";
        case NAME_RVA: return "FuncNameRva";
    }
    return "";
}

uint32_t ExportEntryWrapper::getOrdinal()
{
    if (this->parentDir == NULL) return 0;
    pe::IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return 0;

    DWORD ordinal = static_cast<DWORD>(this->entryNum) + exp->Base;
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

    pe::IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
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
    pe::IMAGE_EXPORT_DIRECTORY* exp = parentDir->exportDir();
    if (exp == NULL) return NULL;

    DWORD* funcRvaPtr = (DWORD*) this->getFuncRvaPtr();
    if (funcRvaPtr == NULL) return NULL;

    char* strPtr = (char*) m_Exe->getContentAt( (*funcRvaPtr), Executable::RVA, 1);
    if (strPtr == NULL) return NULL;

    uint64_t offset = m_Exe->getOffset((BYTE*) strPtr);
    if (offset == INVALID_ADDR) return NULL;

    size_t maxLen = m_Exe->getRawSize() - offset;
    bool isAsciiStr = (pe_util::hasNonPrintable(strPtr, maxLen) == true) ? false : true;
    if (isAsciiStr) {
        return strPtr;
    }
    return NULL;
}

