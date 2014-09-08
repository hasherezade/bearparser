#include "ImportBaseDirWrapper.h"

//---------------------------------
size_t ImportBaseDirWrapper::EntriesLimit = 1000;
size_t ImportBaseEntryWrapper::EntriesLimit = 1000;

bufsize_t ImportBaseEntryWrapper::NameLenLimit = 0xFF;

//---------------------------------

void ImportBaseDirWrapper::addFuncMapping(ImportBaseFuncWrapper *func)
{
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
    clear();
    thunksList.clear();
    thunkToLibMap.clear();

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

