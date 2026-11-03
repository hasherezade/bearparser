#pragma once

#include "DataDirEntryWrapper.h"
#include "ResourceLeafWrapper.h"

#include "rsrc/ResourcesAlbum.h"
#include "rsrc/ResourceContentFactory.h"

#include <map>
#include <set>
#include <vector>


class ResourceDirWrapper : public DataDirEntryWrapper
{
public:

    enum ResourceDirFID {
        NONE = FIELD_NONE,
        CHARACTERISTIC,
        TIMESTAMP,
        MAJOR_VER,
        MINOR_VER,
        NAMED_ENTRIES_NUM,
        ID_ENTRIES_NUM,
        FIELD_COUNTER
    };

    ResourceDirWrapper(PEFile* pe, ResourcesAlbum *resAlbum = NULL, offset_t rawOffset = 0, long depth = 0, long topEntryId = TOP_ENTRY_ROOT, ResourceDirWrapper *rootDir = NULL)
        : DataDirEntryWrapper(pe, pe::DIR_RESOURCE),
        rawOff(rawOffset), dirDepth(depth), album(resAlbum), topEntryID(topEntryId), root(rootDir ? rootDir : this), entriesLeft(0)
    { 
        wrap();
    }

    bool wrap();

    virtual void* getPtr() { return resourceDir(); }
    virtual bufsize_t getSize();

    virtual QString getName() { return "Resources"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);

    bufsize_t getEntriesAreaSize()
    { 
        return static_cast<bufsize_t>(this->getEntriesCount()) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    }
    
    long getDepth() { return this->dirDepth; }

    IMAGE_RESOURCE_DIRECTORY* mainResourceDir();
    ResourcesAlbum* getAlbumPtr() { return album; }

    /* Registers the directory at the given raw offset as expanded in the tree
     * this directory belongs to. Returns false if it was already expanded:
     * a directory is parsed at most once, so entries that form cycles or share
     * children do not make the tree grow exponentially. */
    bool markExpanded(offset_t dirRawOffset) { return root->expandedDirs.insert(dirRawOffset).second; }

    /* Takes one entry from the budget of the tree. Returns false when the budget is spent.
     * The budget is the number of entries that fit in the file: in a well-formed tree
     * every entry occupies its own bytes, but directories of a malformed file may overlap
     * and reuse the same bytes as entries of many other directories. */
    bool takeEntry()
    {
        if (root->entriesLeft == 0) return false;
        root->entriesLeft--;
        return true;
    }
    ResourceDirWrapper* getRoot() { return root; }

private:
    IMAGE_RESOURCE_DIRECTORY* resourceDir();
    offset_t rawOff;
    long dirDepth;
    ResourcesAlbum *album;
    long topEntryID;
    ResourceDirWrapper *root; // the top directory of this tree (this, for the top directory itself)
    std::set<offset_t> expandedDirs; // used only in the root
    size_t entriesLeft; // used only in the root
};

class ResourceEntryWrapper : public PENodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        NAME_ID_ADDR,
        OFFSET_TO_DATA,
        FIELD_COUNTER
    };

    static QString translateType(WORD id);

    ResourceEntryWrapper(PEFile *pe, ResourceDirWrapper *parentDir, size_t entryNumber, long topEntryId, ResourcesAlbum *resAlbum)
        : PENodeWrapper(pe, parentDir, entryNumber), topEntryID(topEntryId), album(resAlbum), childDir(NULL), childLeaf(NULL)
    {
        this->parentDir = parentDir;
        wrap();
    }

    virtual ~ResourceEntryWrapper() { clear(); }

    bool wrap();
    // full structure boundaries
    virtual void* getPtr() { return getEntryPtr(); }
    virtual bufsize_t getSize() { return sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY); }

    virtual QString getName() { return "Resource entry: "+ translateType(getID());}
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::NOT_ADDR; }

    bool isByName();
    bool isDir();

    WORD getID();
    offset_t getChildOffsetToDirectory(); //relative offset!
    offset_t getNameOffset();

    IMAGE_RESOURCE_DIRECTORY_STRING* getNameStr();
    offset_t getChildAddress();

    IMAGE_RESOURCE_DIRECTORY_ENTRY *getEntryPtr();
    ResourcesAlbum* getAlbumPtr() { return album; }
    long getTopEntryID() { return topEntryID; }

protected:
    virtual void clear();

private:
    long topEntryID;
    ResourcesAlbum *album;

    ResourceDirWrapper* parentDir, *childDir;
    ResourceLeafWrapper *childLeaf;
};

