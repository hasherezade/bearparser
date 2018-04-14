#pragma once

#define TOP_ENTRY_ROOT long(-1)

#include "../../ExeNodeWrapper.h"
#include "../ResourceLeafWrapper.h"
#include "ResourceContentFactory.h"

#include <map>
#include <vector>

class ResourcesContainer {
public:
    ResourcesContainer() {}
    virtual ~ResourcesContainer() {} //TODO

    void putWrapper(ResourceContentWrapper* wrapper);
    ResourceContentWrapper* getWrapperAt(size_t index);

    size_t count() { return wrappers.size(); }
    size_t entriesCount();

protected:
    std::vector<ResourceContentWrapper*> wrappers;
};

class ResourcesAlbum {
public:

    ResourcesAlbum(Executable *pe) {}

    virtual ~ResourcesAlbum() { clear(); }

    void putLeaf(ResourceLeafWrapper* leaf, long topEntryId);
    void clear();

    size_t dirsCount() { return allLeafs.size(); }
    size_t entriesCountAt(long topEntryId);
    std::vector<ResourceLeafWrapper*>* entriesAt(long topEntryId);

    //TODO: create ResourceContentWrapper
    void mapIdToLeafType(long topId, pe::resource_type leafType) { idToLeafType[topId] = leafType; }
    void wrapLeafsContent(); // TODO: wrap content on demand - lazy mode
    ResourceContentWrapper* getContentWrapper(ResourceLeafWrapper* leaf) { return this->leafToContentWrapper[leaf]; }

    bool hasType(pe::resource_type typeId) { return (allWrappers.find(typeId) == allWrappers.end()) ? false : true; }
    ResourcesContainer* getResourcesOfType(pe::resource_type typeId);
    std::vector<pe::resource_type> getResourceTypes() const { return allTypes; }

protected:
    void clearLeafsContent();

    void initResourceTypes();
    bool hasTopEntry(long topEntryId) { return (allLeafs.find(topEntryId) == allLeafs.end()) ? false : true; }
   
    std::vector<pe::resource_type> allTypes;
    std::map<pe::resource_type, ResourcesContainer> allWrappers;
    std::map<long, std::vector<ResourceLeafWrapper*> > allLeafs;

    std::map<long, pe::resource_type> idToLeafType; // map topEntryId to leafDataType:  i. e. RT_HTML, case RT_MANIFEST
    std::map<ResourceLeafWrapper*, ResourceContentWrapper*> leafToContentWrapper;
    
};

