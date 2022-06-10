#include "pe/rsrc/ResourcesAlbum.h"
#include "pe/rsrc/ResourceStringsWrapper.h"


void ResourcesContainer::putWrapper(ResourceContentWrapper* wrapper)
{
    if (wrapper == NULL) return;
    //TODO: check if already exist...
    wrappers.push_back(wrapper);
}

ResourceContentWrapper* ResourcesContainer::getWrapperAt(size_t index)
{
    if (index >= wrappers.size()) return NULL;
    return wrappers.at(index);
}

size_t ResourcesContainer::entriesCount()
{
    size_t totalCount = 0;
    size_t wrappersCount = this->count();

    for (size_t i = 0; i < wrappersCount; i++) {
        ResourceContentWrapper* wrapper = this->getWrapperAt(i);
        if (wrapper == NULL) {
            continue;
        }
        size_t count = wrapper->getFieldsCount();
        totalCount += count;
    }
    return totalCount;
}

//----------------------------------------------------------------------
void ResourcesAlbum::clearLeafsContent()
{
    std::map<ResourceLeafWrapper*, ResourceContentWrapper*>::iterator itr;
    for (itr = leafToContentWrapper.begin(); itr != leafToContentWrapper.end(); itr++) {
        ResourceContentWrapper* cw = itr->second;
        delete cw;
    }
    leafToContentWrapper.clear();
}

void ResourcesAlbum::clear()
{
    clearLeafsContent();
    //---
    std::map<ResourceLeafWrapper*, ResourceContentWrapper*>::iterator cntItr;
    for (cntItr = leafToContentWrapper.begin(); cntItr != leafToContentWrapper.end(); cntItr++) {
        ResourceContentWrapper* cntWr = cntItr->second;
        delete cntWr;
    }
    leafToContentWrapper.clear();
    //---
    allLeafs.clear();
    allTypes.clear();
}

void ResourcesAlbum::putLeaf(ResourceLeafWrapper* leaf, long topEntryId)
{
    if (!leaf) return;
    allLeafs[topEntryId].push_back(leaf);
}

void ResourcesAlbum::wrapLeafsContent()
{
    std::map<long, std::vector<ResourceLeafWrapper*> >::iterator itr;
    for (itr = allLeafs.begin(); itr != allLeafs.end(); itr++) {

        std::vector<ResourceLeafWrapper*> &leafVec = itr->second;
        long topEntryId = itr->first;

        for (size_t i = 0; i < leafVec.size(); i++) {
            ResourceLeafWrapper* leaf = leafVec.at(i);
            pe::resource_type type = idToLeafType[topEntryId];
            //printf("topEntryId %d type: %d\n", topEntryId, type);
//TODO: finish it!
            ResourceContentWrapper* cw = ResourceContentFactory::makeResContentWrapper(type, leaf);
            if (cw != NULL) {
                leafToContentWrapper[leaf] = cw;
                this->allWrappers[type].putWrapper(cw);
            }
        }
    }
    initResourceTypes();
}

size_t ResourcesAlbum::entriesCountAt(long topEntryId)
{
    if (hasTopEntry(topEntryId) == false) {
        return 0;
    }
    return allLeafs[topEntryId].size();
}

std::vector<ResourceLeafWrapper*>* ResourcesAlbum::entriesAt(long topEntryId)
{
    if (hasTopEntry(topEntryId) == false) {
        return NULL;
    }
    return &(allLeafs[topEntryId]);
}

ResourcesContainer* ResourcesAlbum::getResourcesOfType(pe::resource_type typeId)
{
    if (hasType(typeId) == false) {
        return NULL;
    }
    return &(allWrappers[typeId]);
}

void ResourcesAlbum::initResourceTypes()
{
    this->allTypes.clear();
    std::map<pe::resource_type, ResourcesContainer>::iterator itr;

    for ( itr = this->allWrappers.begin(); itr != this->allWrappers.end(); itr++ ) {
        pe::resource_type type = itr->first;
        this->allTypes.push_back(type);
    }
}
/*
std::vector<pe::resource_type> ResourcesAlbum::getResourceTypes()
{
    std::vector<pe::resource_type> typesVec;
    std::map<pe::resource_type, ResourcesContainer>::iterator itr;

    for ( itr = allWrappers.begin(); itr != allWrappers.end(); itr++ ) {
        pe::resource_type type = itr->first;
        typesVec.push_back(type);
    }
    return typesVec;
}
*/