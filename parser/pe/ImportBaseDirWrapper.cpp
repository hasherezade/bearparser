#include "ImportBaseDirWrapper.h"

//---------------------------------
size_t ImportBaseDirWrapper::EntriesLimit = 1000;
size_t ImportBaseEntryWrapper::EntriesLimit = 1000;

bufsize_t ImportBaseEntryWrapper::NameLenLimit = 0xFF;

//---------------------------------

void ImportBaseDirWrapper::addFuncMapping(ImportBaseFuncWrapper *func)
{
    uint64_t via = func->callVia();
    if (via == INVALID_ADDR) return;
    /*
    if (m_Exe->isValidVA(via)) {
        via = m_Exe->VaToRva(via);
    }*/
    ImportBaseEntryWrapper* lib = dynamic_cast<ImportBaseEntryWrapper*>(func->getParentNode());
    if (!lib) return;

    size_t num = lib->getEntryId();
    thunkToLibMap[via] = num;

    num = func->getEntryId();
    lib->thunkToFuncMap[via] = num;
}

QString ImportBaseDirWrapper::thunkToFuncName(offset_t thunk)
{
    std::map<offset_t, size_t>::iterator libItr = thunkToLibMap.find(thunk);
    if (libItr == thunkToLibMap.end()) return "";

    size_t libId = libItr->second;
    ImportBaseEntryWrapper* lib = dynamic_cast<ImportBaseEntryWrapper*>(this->getEntryAt(libId));
    if (!lib) return "?";

    std::map<offset_t, size_t>::iterator funcItr = lib->thunkToFuncMap.find(thunk);
    if (funcItr == lib->thunkToFuncMap.end()) return "";

    ImportBaseFuncWrapper* func = dynamic_cast<ImportBaseFuncWrapper*>(lib->getEntryAt(funcItr->second));
    if (!func) return "";

    return func->getName();
}

bool ImportBaseDirWrapper::wrap()
{
    clear();
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


QString ImportBaseFuncWrapper::getName()
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
    ImportBaseEntryWrapper *p = dynamic_cast<ImportBaseEntryWrapper*>(this->getParentNode());
    if (!p) return functionName;

    char *libName = p->getLibraryName();
    if (!libName) return functionName;

    functionName = "[" + QString(libName) + "]." + functionName;
    return functionName;
}

