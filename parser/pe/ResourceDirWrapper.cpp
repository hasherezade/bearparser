#include "ResourceDirWrapper.h"
#include "PEFile.h"

#define MAX_ENTRIES 50
#define MAX_DEPTH 5

/*
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    WORD    NumberOfNamedEntries;
    WORD    NumberOfIdEntries;
    //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;


 // Each directory contains the 32-bit Name of the entry and an offset,
 // relative to the beginning of the resource directory of the data associated
 // with this directory entry.  If the name of the entry is an actual text
 // string instead of an integer Id, then the high order bit of the name field
 // is set to one and the low order 31-bits are an offset, relative to the
 // beginning of the resource directory of the string, which is of type
 // IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
 // low-order 16-bits are the integer Id that identify this resource directory
 // entry. If the directory entry is yet another resource directory (i.e. a
 // subdirectory), then the high order bit of the offset field will be
 // set to indicate this.  Otherwise the high bit is clear and the offset
 // field points to a resource data entry.

#define RESOURCE_NAME_IS_STRING        0x80000000
#define RESOURCE_DATA_IS_DIRECTORY     0x80000000


typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            DWORD NameOffset:31;
            DWORD NameIsString:1;
        } name;
        DWORD   Name;
        WORD    Id;
    };
    union {
        DWORD   OffsetToData;
        struct {
            DWORD   OffsetToDirectory:31;
            DWORD   DataIsDirectory:1;
        } dir;
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

*/
//-------------

IMAGE_RESOURCE_DIRECTORY* ResourceDirWrapper::mainResourceDir()
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(IMAGE_RESOURCE_DIRECTORY));
    return (IMAGE_RESOURCE_DIRECTORY*) ptr;
}

IMAGE_RESOURCE_DIRECTORY* ResourceDirWrapper::resourceDir()
{
    if (this->rawOff == 0) return mainResourceDir();

    BYTE *ptr = m_Exe->getContentAt(this->rawOff, Executable::RAW, sizeof(IMAGE_RESOURCE_DIRECTORY));
    return (IMAGE_RESOURCE_DIRECTORY*) ptr;
}

bool ResourceDirWrapper::wrap()
{
    clear();
    if (this->topEntryID == TOP_ENTRY_ROOT && this->album != NULL) {
        this->album->clear();
    }
    IMAGE_RESOURCE_DIRECTORY* dir = resourceDir();
    if (dir == NULL) return false;
    size_t namesNum = dir->NumberOfNamedEntries;
    size_t idsNum = dir->NumberOfIdEntries;

    size_t totalEntries = namesNum + idsNum;
    for (int i = 0; i < totalEntries && i < MAX_ENTRIES; i++ ) {

        long topDirId = (this->topEntryID != TOP_ENTRY_ROOT) ? this->topEntryID : i ;

        //(PEFileBase *pe, ResourceDirWrapper *parentDir, uint32_t entryNumber, long topEntryId, ResourcesAlbum *resAlbum = NULL)
        ResourceEntryWrapper* entry = new ResourceEntryWrapper(this->m_PE, this, i, topDirId, this->album);

        if (entry->getPtr() == NULL) {
            delete entry;
            break;
        }
        if (this->topEntryID == TOP_ENTRY_ROOT && this->album != NULL) {
            resource_type typeId = static_cast<resource_type>(entry->getID());
            this->album->mapIdToLeafType(i, typeId);
        }
        //this->parsedSize += val;
        this->entries.push_back(entry);
    }
    //printf("Entries: %d\n", getEntriesCount());
    return true;
}


bufsize_t ResourceDirWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    bufsize_t size = sizeof(IMAGE_RESOURCE_DIRECTORY);
    size += getEntriesAreaSize();
    return size;
}

void* ResourceDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    IMAGE_RESOURCE_DIRECTORY* d = resourceDir();
    if (d == NULL) return NULL;

    switch (fId) {
        case CHARACTERISTIC: return &d->Characteristics;
        case TIMESTAMP: return &d->TimeDateStamp;
        case MAJOR_VER: return &d->MajorVersion;
        case MINOR_VER: return &d->MinorVersion;
        case NAMED_ENTRIES_NUM : return &d->NumberOfNamedEntries;
        case ID_ENTRIES_NUM : return &d->NumberOfIdEntries;
        case CHILDREN : return (&d->NumberOfIdEntries) + 1;
    }
    return this->getPtr();
}

QString ResourceDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case CHARACTERISTIC: return "Characteristics";
        case TIMESTAMP: return "TimeDateStamp";
        case MAJOR_VER: return "MajorVersion";
        case MINOR_VER: return "MinorVersion";
        case NAMED_ENTRIES_NUM : return "NumberOfNamedEntries";
        case ID_ENTRIES_NUM : return "NumberOfIdEntries";
        case CHILDREN : return "Entries";
    }
    return getName();
}

//-----------------------------------------------------------------

void ResourceEntryWrapper::clear()
{
    delete childDir;
    this->childDir = NULL;
    //---
    delete childLeaf;
    this->childLeaf = NULL;
}

bool ResourceEntryWrapper::wrap()
{
    clear();
    //---
    offset_t childRaw = getChildAddress();
    if (childRaw == 0 || childRaw == INVALID_ADDR) return false;

    if (this->isDir()) {
        long depth = this->parentDir->getDepth() + 1;
        if (depth >= MAX_DEPTH) return false;
        //printf("Subdir at: %x ,depth : %lld\n", childRaw, depth);
        this->childDir = new ResourceDirWrapper(this->m_PE, this->album, childRaw, depth, topEntryID);
    } else {
        //printf("Leaf at: %x\n", childRaw);
        this->childLeaf = new ResourceLeafWrapper(m_Exe, childRaw, topEntryID);
        //test
        if (this->album != NULL) {
            album->putLeaf(childLeaf, topEntryID);
            //printf("Album: topEntryID: %x\n", topEntryID);
        }
    }
    return true;
}


pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* ResourceEntryWrapper::getEntryPtr()
{
    if (this->parentDir == NULL) return NULL;
    uint64_t offset = parentDir->getFieldOffset(ResourceDirWrapper::ID_ENTRIES_NUM);
    if (offset == INVALID_ADDR) return NULL;

    size_t lastSize = parentDir->getFieldSize(ResourceDirWrapper::ID_ENTRIES_NUM, FIELD_NONE);
    offset += lastSize;
    offset += (this->entryNum * sizeof(pe::IMAGE_RESOURCE_DIRECTORY_ENTRY));

    void *ptr = m_Exe->getContentAt(offset, Executable::RAW, sizeof(pe::IMAGE_RESOURCE_DIRECTORY_ENTRY));
    return (pe::IMAGE_RESOURCE_DIRECTORY_ENTRY*) ptr;
}

//IMAGE_RESOURCE_DIRECTORY_ENTRY
void* ResourceEntryWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = getEntryPtr();
    if (entry == NULL) return NULL;

    switch (fieldId) {
        case NAME_ID_ADDR:
            return &entry->Name;
        case OFFSET_TO_DATA:
            return &entry->OffsetToData;
    }
    return getPtr();
}

QString ResourceEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case NAME_ID_ADDR:
            return(isByName()) ? "Name": "ID";
        case OFFSET_TO_DATA:
            return "Offset To Data";
    }
    return getName();
}

bool ResourceEntryWrapper::isByName()
{
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = getEntryPtr();
    if (entry == NULL) return false;
    if (entry->name.NameIsString == 1) return true;
    return false;
}

bool ResourceEntryWrapper::isDir()
{
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = getEntryPtr();
    if (entry == NULL) return false;
    if (entry->dir.DataIsDirectory == 1) return true;
    return false;
}

offset_t ResourceEntryWrapper::getNameOffset()
{
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = getEntryPtr();
    if (entry == NULL) return INVALID_ADDR;

    if (this->parentDir == NULL) return INVALID_ADDR;
    offset_t fOff = this->parentDir->getOffset(this->parentDir->getPtr());
    if (fOff == INVALID_ADDR) return INVALID_ADDR;

    if (entry->name.NameIsString != 1) return INVALID_ADDR;
    return fOff + entry->name.NameOffset;
}

IMAGE_RESOURCE_DIRECTORY_STRING* ResourceEntryWrapper::getNameStr()
{
    offset_t nameOff = getNameOffset();
    if (nameOff == INVALID_ADDR) return NULL;

    const size_t BASIC_SIZE = sizeof(IMAGE_RESOURCE_DIRECTORY_STRING);
    IMAGE_RESOURCE_DIRECTORY_STRING *ptr = (IMAGE_RESOURCE_DIRECTORY_STRING*) this->m_Exe->getContentAt(nameOff, Executable::RAW, BASIC_SIZE);
    return ptr;
}

QString ResourceEntryWrapper::translateType(WORD id)
{
    switch (id) {
        case RESTYPE_CURSOR : return "Cursor";
        case RESTYPE_FONT :return "Font";
        case RESTYPE_BITMAP : return "Bitmap";
        case RESTYPE_ICON : return "Icon";
        case RESTYPE_MENU : return "Menu";
        case RESTYPE_DIALOG : return "Dialog";
        case RESTYPE_STRING : return "String";
        case RESTYPE_FONTDIR : return "Font Dir";
        case RESTYPE_ACCELERATOR : return "Accelerator";
        case RESTYPE_RCDATA : return "RC Data";
        case RESTYPE_MESSAGETABLE : return "Message Table";

        case RESTYPE_GROUP_CURSOR : return "Cursors Group";
        case RESTYPE_GROUP_ICON : return "Icons Group";
        case RESTYPE_VERSION : return "Version";
        case RESTYPE_DLGINCLUDE : return "Dlg Include";
        case RESTYPE_PLUGPLAY : return "Plug & Play";
        case RESTYPE_VXD : return "VXD";
        case RESTYPE_ANICURSOR : return "Animated Cursor";
        case RESTYPE_ANIICON : return "Animated Icon";
        case RESTYPE_HTML : return "HTML";
        case RESTYPE_MANIFEST : return "Manifest";
    }
    return "";
}

WORD ResourceEntryWrapper::getID()
{
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = getEntryPtr();
    if (entry == NULL) return 0;
    if (this->isByName()) return 0;

    return entry->Id;
}

DWORD ResourceEntryWrapper::getChildOffsetToDirectory()
{
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY* entry = getEntryPtr();
    if (entry == NULL) return 0;
    return entry->dir.OffsetToDirectory;
}

offset_t ResourceEntryWrapper::getChildAddress()
{
    if (this->parentDir == NULL) return INVALID_ADDR;
    offset_t fOff = this->parentDir->getOffset(this->parentDir->mainResourceDir());
    if (fOff == INVALID_ADDR) return INVALID_ADDR;

    fOff += static_cast<offset_t>(getChildOffsetToDirectory());
    return fOff;
}

//-------------------------------------------------------------------------

IMAGE_RESOURCE_DATA_ENTRY* ResourceLeafWrapper::leafEntryPtr()
{
    if (this->offset == 0 || this->offset == INVALID_ADDR) return NULL;

    IMAGE_RESOURCE_DATA_ENTRY* leaf = (IMAGE_RESOURCE_DATA_ENTRY*) this->m_Exe->getContentAt(this->offset, Executable::RAW, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
    return leaf;
}

void* ResourceLeafWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    IMAGE_RESOURCE_DATA_ENTRY* leaf = leafEntryPtr();
    if (leaf == NULL) return NULL;

    switch (fieldId) {
        case OFFSET_TO_DATA: return &leaf->OffsetToData;
        case DATA_SIZE: return &leaf->Size;
        case CODE_PAGE: return &leaf->CodePage;
        case RESERVED: return &leaf->Reserved;
    }
    return NULL;
}

QString ResourceLeafWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case OFFSET_TO_DATA: return "OffsetToData";
        case DATA_SIZE: return "DataSize";
        case CODE_PAGE: return "CodePage";
        case RESERVED: return "Reserved";
    }
    return "";
}


