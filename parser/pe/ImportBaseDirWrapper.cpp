#include "pe/ImportBaseDirWrapper.h"

//---------------------------------

bufsize_t ImportBaseEntryWrapper::NameLenLimit = 0xFF;

bool imports_util::isNameValid(Executable *pe, char* myName)
{
    if (!myName) return false; // do not parse, invalid entry
    bufsize_t upperLimit = pe->getMaxSizeFromPtr((BYTE*) myName);
    if (upperLimit == 0) return false;

    bool isInvalid = pe_util::hasNonPrintable(myName, upperLimit);
    if (isInvalid) return false;
    if (pe_util::noWhiteCount(myName) == 0) return false;

    return true;
}
//---------------------------------

using namespace imports_util;

bufsize_t ImportBaseDirWrapper::thunkSize(Executable::exe_bits bits) {
    if (bits == Executable::BITS_32) return sizeof (uint32_t);
    else if (bits == Executable::BITS_64) return sizeof (uint64_t);
    return 0;
}


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

    for (size_t i = 0; i < entriesCount; i++) {
        ImportBaseEntryWrapper* lib = dynamic_cast<ImportBaseEntryWrapper*> (this->getEntryAt(i));
        if (lib == NULL) continue;
        size_t libId = lib->entryNum;

        size_t funcCount = lib->getEntriesCount();
        for (size_t fI = 0; fI < funcCount; fI++) {
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

QString ImportBaseDirWrapper::thunkToFuncName(offset_t thunk, bool shortName)
{
    ImportBaseFuncWrapper* func = thunkToFunction(thunk);
    if (func == NULL) return "";
    if (shortName) {
        return func->getShortName();
    }
    return func->getName();
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

    const size_t LIMIT = (-1);
    const size_t INVALID_LIMIT = 100;
    size_t cntr = 0;
    size_t invalidSeries = 0;
    for (cntr = 0; cntr < LIMIT; cntr++) {
        if (loadNextEntry(cntr) == false) break;
        ExeNodeWrapper* entry = this->entries.at(cntr);
        if (!entry) break;
        if (entry->isValid()) {
            invalidSeries = 0;
        }
        else {
            invalidSeries++;
            if (invalidSeries >= INVALID_LIMIT) break;
        }
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

    const size_t LIMIT = (-1);
    const size_t INVALID_LIMIT = 100;
    if (!isValid()) {
        return false;
    }

    if (this->getPtr() == NULL) {
        return false;
    }

    size_t cntr = 0;
    size_t invalidSeries = 0;
    
    for (cntr = 0; cntr < LIMIT; cntr++) {
        if (loadNextEntry(cntr) == false) break;
        ExeNodeWrapper* entry = this->entries.at(cntr);
        if (!entry) break;
        if (entry->isValid()) {
            invalidSeries = 0;
        }
        else {
            invalidSeries++;
            if (invalidSeries >= INVALID_LIMIT) break;
        }
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
        QString out;
#if QT_VERSION >= 0x050000
        out = QString::asprintf("<ord: %llX>", static_cast<unsigned long long>(val));
#else
        out.sprintf("<ord: %llX>", static_cast<unsigned long long>(val));
#endif
        functionName = out;
    } else {
        char *fName = this->getFunctionName();
        if (!fName) return "";
        functionName = fName;
    }
    return functionName;
}

QString ImportBaseFuncWrapper::getLibName()
{
    ImportBaseEntryWrapper *p = dynamic_cast<ImportBaseEntryWrapper*>(this->getParentNode());
    if (!p) return "";
    
    char *libName = p->getLibraryName();
    if (!libName) return "";
    
    return QString(libName);
}

QString ImportBaseFuncWrapper::getName()
{
    QString libName = getLibName();
    QString functionName = getShortName();

    if (!libName.length()) return functionName;

    return "[" + QString(libName) + "]." + functionName;
}

