#include "BoundImpDirWrapper.h"
#include "PEFile.h"

using namespace pe;
uint64_t BoundImpDirWrapper::EntriesLimit = 1000;

/*
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

*/

pe::IMAGE_BOUND_IMPORT_DESCRIPTOR* BoundImpDirWrapper::boundImp()
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(pe::IMAGE_BOUND_IMPORT_DESCRIPTOR));
    if (ptr == NULL) return NULL;
    return (pe::IMAGE_BOUND_IMPORT_DESCRIPTOR*) ptr;
}

bool BoundImpDirWrapper::wrap()
{
    clear();

    uint64_t cntr = 0;
    if (!getDataDirectory()) {
        if (this->importsCount == cntr) return false;
        this->importsCount = cntr;
        return true;
    }

    const uint32_t LIMIT = BoundImpDirWrapper::EntriesLimit;//(-1);
    BoundEntryWrapper* imp = NULL;
    bool isNext = false;

    for (cntr = 0; cntr < EntriesLimit; cntr++) {
        isNext = false;

        imp = new BoundEntryWrapper(m_Exe, this, cntr);
        if (!imp || !imp->getPtr()) break;

        // TODO! do it in proper way!
        bool isOk = false;
        uint64_t offset = imp->getNumValue(BoundEntryWrapper::MODULE_NAME_OFFSET, &isOk);
        if (!isOk || offset == 0) {
            //will be deleted at the end
            break;
        }
        //printf("Name = %s\n", imp->getName().c_str());
        entries.push_back(imp);
        isNext = true;
    }
    if (!isNext) delete imp;
    //printf ("entries = %d\n", entries.size());

    if (this->importsCount == cntr) return false;
    this->importsCount = cntr;
    return true;
}

bufsize_t BoundImpDirWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    bufsize_t entrySize = static_cast<bufsize_t>(sizeof(pe::IMAGE_BOUND_IMPORT_DESCRIPTOR));
    return entrySize * static_cast<bufsize_t>(this->entries.size());
}

//-------------------------------------------------------------

void* BoundEntryWrapper::getPtr()
{
    BoundImpDirWrapper* parent = dynamic_cast<BoundImpDirWrapper*> (this->getParentNode());
    if (!parent) return NULL;

    pe::IMAGE_BOUND_IMPORT_DESCRIPTOR* firstEntry = parent->boundImp();
    if (firstEntry == NULL) return NULL;

    uint64_t descAddr = parent->getOffset(firstEntry);
    if (descAddr == INVALID_ADDR) return NULL;

    uint64_t entryOffset = descAddr + (this->entryNum * sizeof(pe::IMAGE_BOUND_IMPORT_DESCRIPTOR));
    if (entryOffset == INVALID_ADDR) return NULL;

    BYTE *content =  this->m_Exe->getContentAt(entryOffset, Executable::RAW, sizeof(pe::IMAGE_BOUND_IMPORT_DESCRIPTOR));
    if (!content) return NULL;

    return content;
}


bufsize_t BoundEntryWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    return sizeof(pe::IMAGE_BOUND_IMPORT_DESCRIPTOR);
}

QString BoundEntryWrapper::getName()
{
    char* name = getLibraryName();
    if (!name) return "";
    return QString(name);
}

char* BoundEntryWrapper::getLibraryName()
{
    //----
    BoundImpDirWrapper* parent = dynamic_cast<BoundImpDirWrapper*> (this->getParentNode());
    if (!parent) return NULL;

    pe::IMAGE_BOUND_IMPORT_DESCRIPTOR* firstEntry = parent->boundImp();
    if (firstEntry == NULL) return NULL;

    uint64_t offset = this->getOffset(firstEntry);
    if (offset == INVALID_ADDR) return NULL;
    //----
    pe::IMAGE_BOUND_IMPORT_DESCRIPTOR* bImp = (pe::IMAGE_BOUND_IMPORT_DESCRIPTOR*) this->getPtr();
    if (bImp == NULL) return NULL;

    WORD mnOff = bImp->OffsetModuleName;

    offset += mnOff;

    char *ptr = (char*) m_Exe->getContentAt(offset, Executable::RAW, 1);
    return ptr;
}

void* BoundEntryWrapper::getFieldPtr(size_t fId, size_t subField)
{
    BoundImpDirWrapper* parent = dynamic_cast<BoundImpDirWrapper*> (this->getParentNode());
    if (!parent) return NULL;

    pe::IMAGE_BOUND_IMPORT_DESCRIPTOR* bImp = (pe::IMAGE_BOUND_IMPORT_DESCRIPTOR*) this->getPtr();
    if (bImp == NULL) return NULL;

    switch (fId) {
        case TIMESTAMP : return &bImp->TimeDateStamp;
        case MODULE_NAME_OFFSET : return &bImp->OffsetModuleName;
        case MODULE_FORWARDERS_NUM : return &bImp->NumberOfModuleForwarderRefs;
    }
    return this->getPtr();
}

QString BoundEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case TIMESTAMP : return "TimeDateStamp";
        case MODULE_NAME_OFFSET : return "OffsetModuleName";
        case MODULE_FORWARDERS_NUM : return "NumberOfModuleForwarderRefs";
    }
    return getName();
}

