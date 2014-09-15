#include "ImportBaseDirWrapper.h"

//---------------------------------
size_t ImportBaseDirWrapper::EntriesLimit = 1000;
size_t ImportBaseEntryWrapper::EntriesLimit = 1000;

bufsize_t ImportBaseEntryWrapper::NameLenLimit = 0xFF;

using namespace imports_util;

bufsize_t ImportBaseDirWrapper::thunkSize(Executable::exe_bits bits) {
    if (bits == Executable::BITS_32) return sizeof (uint32_t);
    else if (bits == Executable::BITS_64) return sizeof (uint64_t);
    return 0;
}

//TODO: refector it!
inline uint64_t imports_util::getUpperLimit(Executable *pe, void* fieldPtr)
{
    if (!pe || ! fieldPtr) return 0;

    offset_t nameOffset = pe->getOffset((BYTE*)fieldPtr);
    if (nameOffset == INVALID_ADDR) return 0;

    int64_t upperLimit = pe->getRawSize() - nameOffset;
    if (upperLimit < 0) return 0;
    return upperLimit;
}

inline bool imports_util::isNameValid(Executable *pe, char* myName)
{
    if (!myName) return false; // do not parse, invalid entry

    uint64_t upperLimit = getUpperLimit(pe, myName);
    if (upperLimit == 0) return false;

    bool isInvalid = pe_util::hasNonPrintable(myName, upperLimit);
    if (isInvalid) return false;
    if (pe_util::noWhiteCount(myName) == 0) return false;

    return true;
}
//---------------------------------

void ImportBaseDirWrapper::addMapping(ExeNodeWrapper *funcNode)
{
    ImportBaseFuncWrapper* func = dynamic_cast<ImportBaseFuncWrapper*> (funcNode);
    if (func == NULL) return;

    offset_t via = func->callVia();
    if (via == INVALID_ADDR) return;
    /*
    if (m_Exe->isValidVA(via)) {
        via = m_Exe->VaToRva(via);
    }*/
    ImportBaseEntryWrapper* lib = dynamic_cast<ImportBaseEntryWrapper*>(func->getParentNode());
    if (!lib) return;

    this->thunksList.push_back(via);
    size_t num = lib->getEntryId();
    thunkToLibMap[via] = num;

    num = func->getEntryId();
    lib->thunkToFuncMap[via] = num;
}

void ImportBaseDirWrapper::clearMapping()
{
    thunksList.clear();
    thunkToLibMap.clear();
}


void ImportBaseDirWrapper::reloadMapping()
{
    clearMapping();
    size_t entriesCount = this->entries.size();

    for (int i = 0; i < entriesCount; i++) {
        ImportBaseEntryWrapper* lib = dynamic_cast<ImportBaseEntryWrapper*> (this->getEntryAt(i));
        if (lib == NULL) continue;
        size_t libId = lib->entryNum;

        size_t funcCount = lib->getEntriesCount();
        for (int fI = 0; fI < funcCount; fI++) {
            addMapping(lib->getEntryAt(fI));
        }
    }
}

ImportBaseEntryWrapper* ImportBaseDirWrapper::thunkToLib(offset_t thunk)
{
    std::map<offset_t, size_t>::iterator libItr = thunkToLibMap.find(thunk);
    if (libItr == thunkToLibMap.end()) return NULL;

    size_t libId = libItr->second;
    ImportBaseEntryWrapper* lib = dynamic_cast<ImportBaseEntryWrapper*>(this->getEntryAt(libId));
    return lib;
}

ImportBaseFuncWrapper* ImportBaseDirWrapper::thunkToFunction(offset_t thunk)
{
    ImportBaseEntryWrapper* lib = thunkToLib(thunk);
    if (!lib) return NULL;

    std::map<offset_t, size_t>::iterator funcItr = lib->thunkToFuncMap.find(thunk);
    if (funcItr == lib->thunkToFuncMap.end()) return NULL;

    ImportBaseFuncWrapper* func = dynamic_cast<ImportBaseFuncWrapper*>(lib->getEntryAt(funcItr->second));
    return func;
}

QString ImportBaseDirWrapper::thunkToFuncName(offset_t thunk)
{
    ImportBaseFuncWrapper* func = thunkToFunction(thunk);
    if (func == NULL) return "";

    return func->getShortName();
}

QString ImportBaseDirWrapper::thunkToLibName(offset_t thunk)
{
    ImportBaseEntryWrapper* lib = thunkToLib(thunk);
    if (!lib) return "";
    return lib->getName();
}

bool ImportBaseDirWrapper::wrap()
{
    clearMapping();
    clear();

    size_t oldCount = this->importsCount;
    this->importsCount = 0;

    if (!getDataDirectory()) {
        return (oldCount != this->importsCount); //has count changed
    }

    const size_t LIMIT = ImportBaseDirWrapper::EntriesLimit;

    size_t cntr = 0;
    for (cntr = 0; cntr < LIMIT; cntr++) {
        if (loadNextEntry(cntr) == false) break;
    }

    this->importsCount = cntr;
    return (oldCount != this->importsCount); //has count changed
}

//--------------------------------------------------------------------------------------------------------------

bool ImportBaseEntryWrapper::isValid()
{
    char *libName = this->getLibraryName();
    bool isValid = imports_util::isNameValid(m_Exe, libName);
    return isValid;
}

bool ImportBaseEntryWrapper::wrap()
{
    clear();
    thunkToFuncMap.clear();

    const size_t LIMIT = ImportBaseEntryWrapper::EntriesLimit;
   if (!isValid()) {
        return false;
    }
    size_t cntr = 0;
    if (this->getPtr() == NULL) {
        return false;
    }
    for (cntr = 0; cntr < LIMIT; cntr++) {
        if (loadNextEntry(cntr) == false) break;
    }
    //printf("Entries: %d\n", entries.size());
    return true;
}

//--------------------------------------------------------------------------------------------------------------
QString ImportBaseFuncWrapper::getShortName()
{
    QString functionName;
    if (isByOrdinal()) {
        uint64_t val = getOrdinal();
        static char buf[0xFF];
        snprintf(buf, 0xFF, "<ord: %llX>", val);
        functionName = buf;
    } else {
        char *fName = this->getFunctionName();
        if (!fName) return "";
        functionName = fName;
    }
    return functionName;
}

QString ImportBaseFuncWrapper::getName()
{
    QString functionName = getShortName();
    ImportBaseEntryWrapper *p = dynamic_cast<ImportBaseEntryWrapper*>(this->getParentNode());
    if (!p) return functionName;

    char *libName = p->getLibraryName();
    if (!libName) return functionName;

    functionName = "[" + QString(libName) + "]." + functionName;
    return functionName;
}

