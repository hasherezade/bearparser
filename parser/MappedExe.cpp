#include "MappedExe.h"

void ExeWrappersContainer::clearWrappers()
{
    std::map<int, ExeElementWrapper*>::iterator itr;
    for (itr = this->wrappers.begin(); itr != this->wrappers.end(); itr++){
        ExeElementWrapper* wrapper = itr->second;
        delete wrapper;
    }
    wrappers.clear();
}

ExeElementWrapper* ExeWrappersContainer::getWrapper(int wrapperId)
{
    if (wrappers.find(wrapperId) == wrappers.end()) return NULL;
    return wrappers[wrapperId];
}

QString ExeWrappersContainer::getWrapperName(int id)
{
    if (wrappers.find(id) == wrappers.end()) return "";
    return wrappers[id]->getName();
}
