#include "pe/SectHdrsWrapper.h"
#include "pe/PEFile.h"

using namespace buf_util;

const size_t SectionHdrWrapper::SECNAME_LEN = 8;

size_t SectHdrsWrapper::SECT_COUNT_MAX = 0x2000;
size_t SectHdrsWrapper::SECT_INVALID_INDEX = SIZE_MAX;

std::map<DWORD, QString> SectionHdrWrapper::s_secHdrCharact;

QString SectionHdrWrapper::getSecHdrAccessRightsDesc(DWORD characteristics)
{
    char rights[] = "---";

    if (characteristics & SCN_MEM_READ)
        rights[0] = 'r';
    if (characteristics & SCN_MEM_WRITE)
        rights[1] = 'w';
    if (characteristics & SCN_MEM_EXECUTE)
        rights[2] = 'x';
    return rights;
}

void SectionHdrWrapper::initSecCharacter(std::map<DWORD, QString> &secHdrCharact)
{
    secHdrCharact[SCN_MEM_READ] = "readable";
    secHdrCharact[SCN_MEM_WRITE] = "writeable";
    secHdrCharact[SCN_MEM_EXECUTE] = "executable";

    secHdrCharact[SCN_LNK_NRELOC_OVFL] = "contains extended relocations";
    secHdrCharact[SCN_MEM_DISCARDABLE] = "discardable";
    secHdrCharact[SCN_MEM_NOT_CACHED] = "not cachable";
    secHdrCharact[SCN_MEM_NOT_PAGED] = "pageable";
    secHdrCharact[SCN_MEM_SHARED] = "shareable";
    secHdrCharact[SCN_CNT_CODE] = "code";
    secHdrCharact[SCN_CNT_INITIALIZED_DATA] = "initialized data";
    secHdrCharact[SCN_CNT_UNINITIALIZED_DATA] = "uninitialized data";
}

std::vector<DWORD> SectionHdrWrapper::splitCharacteristics(DWORD charact)
{
    if (s_secHdrCharact.size() == 0) {
        initSecCharacter(s_secHdrCharact);
    }
    std::vector<DWORD> chSet;
    std::map<DWORD, QString>::iterator iter;
    for (iter = s_secHdrCharact.begin(); iter != s_secHdrCharact.end(); iter++) {
        if (charact & iter->first) {
            chSet.push_back(iter->first);
        }
    }
    return chSet;
}

QString SectionHdrWrapper::translateCharacteristics(DWORD charact)
{
    if (s_secHdrCharact.size() == 0) {
        initSecCharacter(s_secHdrCharact);
    }

    if (s_secHdrCharact.find(charact) == s_secHdrCharact.end()) return "";
    return s_secHdrCharact[charact];
}

//----

bool SectionHdrWrapper::wrap()
{
    this->clear();

    this->header = NULL;
    getPtr();
    reloadName();
    return true;
}

void* SectionHdrWrapper::getPtr()
{
    if (m_PE == NULL) return NULL;

    if (header != NULL) {
        return (void*) this->header;
    }

    offset_t firstSecOffset = m_PE->secHdrsOffset();
    offset_t secOffset = firstSecOffset + (this->sectNum * sizeof(IMAGE_SECTION_HEADER));

    //cache the header:
    this->header = (IMAGE_SECTION_HEADER*) m_PE->getContentAt(secOffset, sizeof(IMAGE_SECTION_HEADER));
    return (void*) this->header;
}

bool SectionHdrWrapper::reloadName()
{
    IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*) getPtr();
    if (!header) return false;

    if (this->name) {
        if (memcmp(this->name, header->Name, SECNAME_LEN) == 0) {
            return true; //no need to reload
        }
    }
    const size_t BUF_LEN = SECNAME_LEN + 2;
    if (!this->name) {
        this->name = (char*)::calloc(BUF_LEN, 1);
    }
    memset(this->name, 0, BUF_LEN);
    snprintf(this->name, BUF_LEN, "%.8s", (char*) header->Name);
    this->mappedName = this->name;
    if (this->mappedName.length() == 0) {
        this->mappedName = "#" + QString::number(this->sectNum, 10);
    }
    return true;
}

bufsize_t SectionHdrWrapper::getSize()
{
    if (m_PE == NULL) return 0;
    return sizeof(IMAGE_SECTION_HEADER);
}

QString SectionHdrWrapper::getName()
{
    //reloadName();
    if (!this->name) return ""; //cannot load
    return this->name;
}

void* SectionHdrWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*) getPtr();
    if (!sec) return NULL;
    if (!this->name) return NULL;
    switch (fieldId)
    {
        case NAME: return (void*) &sec->Name;
        case VSIZE: return (void*) &sec->Misc.VirtualSize;
        case VPTR: return (void*) &sec->VirtualAddress;
        case RSIZE: return (void*) &sec->SizeOfRawData;
        case RPTR: return(void*) &sec->PointerToRawData;

        case RELOC_PTR: return (void*) &sec->PointerToRelocations;
        case RELOC_NUM: return (void*) &sec->NumberOfRelocations;
        case LINENUM_PTR: return (void*) &sec->PointerToLinenumbers;
        case LINENUM_NUM: return (void*) &sec->NumberOfLinenumbers;

        case CHARACT: return (void*) &sec->Characteristics;
    }
    return this->getPtr();
}

QString SectionHdrWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId)
    {
        case NAME: return "Name";
        case VSIZE: return "Virtual Size";
        case VPTR: return "Virtual Addr.";
        case RSIZE: return "Raw size";
        case RPTR: return "Raw Addr.";
        case CHARACT: return "Characteristics";
        case RELOC_PTR: return "Ptr to Reloc.";
        case RELOC_NUM: return "Num. of Reloc.";
        case LINENUM_PTR: return "Ptr to Linenum.";
        case LINENUM_NUM: return "Num. of Linenum.";
    }
    return "";
}

Executable::addr_type SectionHdrWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId)
    {
        case VPTR: return Executable::RVA;
        case RPTR: return Executable::RAW;
        //case RELOC_PTR: return Executable::RAW;
    }
    return Executable::NOT_ADDR;
}

WrappedValue::data_type SectionHdrWrapper::containsDataType(size_t fieldId, size_t subField)
{
    if (fieldId == NAME) {
        return WrappedValue::STRING;
    }
    return WrappedValue::INT;
}


// offset that is declared in header
offset_t SectionHdrWrapper::getContentDeclaredOffset(Executable::addr_type aType)
{
    if (this->header == NULL) return INVALID_ADDR;
    offset_t offset = INVALID_ADDR;

    if (aType == Executable::RAW) {
        offset = static_cast<offset_t>(this->header->PointerToRawData);//(this->getNumValue(RPTR, &isOk));
    } else if (aType == Executable::VA || aType == Executable::RVA) {
        offset = static_cast<offset_t>(this->header->VirtualAddress);//this->getNumValue(VPTR, &isOk));
    }
    return offset;
}

offset_t SectionHdrWrapper::getContentOffset(Executable::addr_type aType, bool useMapped)
{
    offset_t offset = getContentDeclaredOffset(aType);
    if (!useMapped) {
        return offset; //returning as is
    }
    if (aType == Executable::RAW) {
        const size_t peSize = m_PE->getMappedSize(aType);
        if (offset > peSize) {
            offset = INVALID_ADDR;
        }
    }
    return offset;
}

offset_t SectionHdrWrapper::getContentEndOffset(Executable::addr_type addrType, bool recalculate)
{
    const bool useMapped = true;
    offset_t startOffset = getContentOffset(addrType, useMapped);
    if (startOffset == INVALID_ADDR) return INVALID_ADDR;

    offset_t endOffset = static_cast<offset_t>(getContentSize(addrType, recalculate)) + startOffset;
    return endOffset;
}

// size that is declared in header
bufsize_t SectionHdrWrapper::getContentDeclaredSize(Executable::addr_type aType)
{
    if (this->header == NULL) return 0;
    bufsize_t size = 0;

    if (aType == Executable::RAW) {
        size = static_cast<bufsize_t>(this->header->SizeOfRawData);//this->getNumValue(RSIZE, &isOk));
    } else if (aType == Executable::VA || aType == Executable::RVA) {
        size = static_cast<bufsize_t>(this->header->Misc.VirtualSize);//this->getNumValue(VSIZE, &isOk));
    }
    return size;
}

//RAW size that is really mapped
bufsize_t SectionHdrWrapper::getMappedRawSize()
{
    const Executable::addr_type aType = Executable::RAW;

    const offset_t secOffset = getContentOffset(aType);
    if (secOffset == INVALID_ADDR) {
        return 0; //invalid addr, nothing is mapped
    }
    const bufsize_t dRawSize = getContentDeclaredSize(aType);
    if (dRawSize == 0) {
        return 0; // no changes
    }

    const bufsize_t peSize = m_PE->getRawSize();
    if (secOffset > peSize) {
        return 0; //out of scope
    }
    bufsize_t roundedUpSize = dRawSize;
    bufsize_t unit = m_PE->getAlignment(aType);
    if (unit != 0) {
        roundedUpSize = roundupToUnit(dRawSize, unit);
    }
    const bufsize_t secEnd = secOffset + roundedUpSize;
    
    //trim to the file size:
    if (secEnd > peSize) {
        const bufsize_t trimmedSize = peSize - secOffset; // trim to the file size
        bufsize_t virtualSize = getContentDeclaredSize(Executable::RVA);
        if (virtualSize) {
            bufsize_t unit = m_PE->getAlignment(Executable::RVA);
            if (unit != 0) {
                virtualSize = roundupToUnit(virtualSize, unit);
            }
        }
        if ((virtualSize != 0) && (trimmedSize > virtualSize)) {
            return virtualSize;
        }
        return trimmedSize;
    }
    return roundedUpSize;
}

//VirtualSize that is really mapped
bufsize_t SectionHdrWrapper::getMappedVirtualSize()
{
    if (!m_PE) return 0;

    const Executable::addr_type aType = Executable::RVA;

    const offset_t startOffset = getContentOffset(aType);
    if (startOffset == INVALID_ADDR) {
        return 0; //invalid addr, nothing is mapped
    }

    bufsize_t dVirtualSize = getContentDeclaredSize(aType);
    bufsize_t mRawSize = getMappedRawSize();

    bufsize_t mVirtualSize = (dVirtualSize > mRawSize) ? dVirtualSize : mRawSize;
    bufsize_t unit = m_PE->getAlignment(aType);
    if (unit) {
        mVirtualSize = roundupToUnit(mVirtualSize, unit);
    }
    // trim to Image Size:
    const bufsize_t secEnd = startOffset + mVirtualSize;
    const bufsize_t imgSize = m_PE->getImageSize();
    if (secEnd > imgSize) {
        const bufsize_t trimmedSize = imgSize - startOffset;
        return trimmedSize;
    }
    return mVirtualSize;
}

bufsize_t SectionHdrWrapper::getContentSize(Executable::addr_type aType, bool recalculate)
{
    if (!this->header || !m_PE) return 0;

    bufsize_t size = 0;
    if (!recalculate) {
        size = getContentDeclaredSize(aType);
        //printf("Declared size = %llx\n---\n", size);
        return size;
    }
    //---
    if (aType == Executable::RAW) {
        //printf ("R: ");
        size = getMappedRawSize();
    }
    if (aType == Executable::RVA || aType == Executable::VA) {
        size = getMappedVirtualSize();
        //printf ("V: ");
    }
    //printf("Mapped size = %llx\n", size);
    return size;
}

//-----------------------------------------------------------------------------------

bool SectHdrsWrapper::isMyEntryType(ExeNodeWrapper *entry)
{
    SectionHdrWrapper* sEntry = dynamic_cast<SectionHdrWrapper*> (entry);
    if (sEntry == NULL) {
        return false;
    }
    return true;
}

bool SectHdrsWrapper::canAddEntry()
{
    offset_t nextOffset = getNextEntryOffset();
    bufsize_t entrySize = geEntrySize();
    if (entrySize == 0) return false;

    bufsize_t paddedSize = entrySize;
    bool haveSpace = this->m_Exe->isAreaEmpty(nextOffset, paddedSize);
    return haveSpace;
}

ExeNodeWrapper* SectHdrsWrapper::addEntry(ExeNodeWrapper *entry)
{
    if (m_PE == NULL) return NULL;

    size_t secCount = m_PE->hdrSectionsNum();
    if (secCount == SECT_COUNT_MAX) return NULL; //limit exceeded

    if (ExeNodeWrapper::addEntry(entry) == NULL) return NULL;
    
    size_t count = secCount + 1;
    if (m_PE->setHdrSectionsNum(count) == false) {
        return NULL;
    }
    return getLastEntry();
}

void SectHdrsWrapper::clear()
{
    ExeNodeWrapper::clear();
    this->rSec.clear();
    this->vSec.clear();
}

bool SectHdrsWrapper::loadNextEntry(size_t entryNum)
{
    SectionHdrWrapper *sec = new SectionHdrWrapper(this->m_PE, entryNum);
    if (sec == NULL) return false;
    if (sec->getPtr() == NULL) {
        Logger::append(Logger::D_WARNING, "Deleting invalid section...");
        delete sec;
        sec = NULL;
        return false;
    }
    this->entries.push_back(sec);
    addMapping(sec);
    return true;
}

void SectHdrsWrapper::addMapping(SectionHdrWrapper *sec)
{
    if (sec == NULL) return;

    bool roundup = true;
    if (sec->getContentSize(Executable::RAW, true) == 0) {
        //printf("skipping empty section..\n");
        return;
    }
    offset_t RVA =sec->getContentOffset(Executable::RVA);
    offset_t raw =sec->getContentOffset(Executable::RAW);

    offset_t endRVA = sec->getContentEndOffset(Executable::RVA, roundup);
    offset_t endRaw = sec->getContentEndOffset(Executable::RAW, roundup);
    vSec[endRVA] = sec;

    if (rSec.find(endRaw) != rSec.end()) { //already exist
        SectionHdrWrapper* prevSec = rSec[endRaw];
        if (prevSec == NULL) return;
        if (prevSec->getContentOffset(Executable::RAW) < sec->getContentOffset(Executable::RAW)) {
            //printf("endRaw = %llX - SKIP\n", endRaw);
            return; //skip
        }
    }
    rSec[endRaw] = sec;
    return;
}

void SectHdrsWrapper::reloadMapping()
{
    this->rSec.clear();
    this->vSec.clear();

    size_t count = this->getEntriesCount();
    for (size_t i = 0; i < count; i++) {
        SectionHdrWrapper* sec = dynamic_cast<SectionHdrWrapper*>(this->getEntryAt(i));
        if (sec == NULL) continue;
        addMapping(sec);
    }
}
    
bool SectHdrsWrapper::wrap()
{
    this->clear();
    if (this->m_PE == NULL) return false;

    size_t count = this->m_PE->hdrSectionsNum();

    for (size_t i = 0; i < count; i++) {
        if (this->loadNextEntry(i) == false) break;
    }
    return true;
}

size_t SectHdrsWrapper::getFieldsCount()
{
    return this->entries.size();
}

void* SectHdrsWrapper::getPtr()
{
    if (entries.size() == 0) return NULL;
    return entries[0]->getPtr();
}

bufsize_t SectHdrsWrapper::getSize()
{
    if (this->m_PE == NULL) return 0;

    size_t secCount = getFieldsCount();

    offset_t hdrOffset = m_PE->secHdrsOffset();
    offset_t fileSize = m_PE->getRawSize();
    offset_t endOffset = hdrOffset + (secCount * sizeof(IMAGE_SECTION_HEADER));

    if (endOffset > fileSize) {
        return bufsize_t (fileSize - hdrOffset);
    }
    return bufsize_t (endOffset - hdrOffset);
}
/*
void* SectHdrsWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    if (fieldId >= entries.size()) return NULL;
    return entries[fieldId]->getFieldPtr(subField);
}
*/
QString SectHdrsWrapper::getFieldName(size_t fieldId)
{
    if (fieldId >= entries.size()) return NULL;
    return entries[fieldId]->getName();
}

SectionHdrWrapper* SectHdrsWrapper::getSecHdrAtOffset(offset_t offset, Executable::addr_type addrType, bool recalculate, bool verbose)
{
    size_t size = this->entries.size();
    std::map<offset_t, SectionHdrWrapper*> *secMap = NULL;

    if (addrType == Executable::RAW) {
        secMap = &this->rSec;
    } else if (addrType == Executable::RVA || addrType == Executable::VA) {
        secMap = &this->vSec;
    }
    if (secMap == NULL) return NULL;

    std::map<offset_t, SectionHdrWrapper*>::iterator found = secMap->lower_bound(offset);
    std::map<offset_t, SectionHdrWrapper*>::iterator itr;
    for (itr = found; itr != secMap->end(); itr++) {
        SectionHdrWrapper* sec = itr->second;
        if (sec == NULL) continue; //TODO: check it
        if (verbose) {
            printf("found [%llX] key: %llX sec: %llX %llX\n", 
                static_cast<unsigned long long>(offset), 
                static_cast<unsigned long long>(itr->first), 
                static_cast<unsigned long long>(sec->getContentOffset(addrType)), 
                static_cast<unsigned long long>(sec->getContentEndOffset(addrType, false))
            );
        }

        offset_t startOffset = sec->getContentOffset(addrType);
        if (startOffset == INVALID_ADDR) continue;

        offset_t endOffset = sec->getContentEndOffset(addrType, recalculate);

        if (offset >= startOffset && offset < endOffset) {
            return sec;
        }
        if (offset < startOffset) break;
    }
    return NULL;
}

void SectHdrsWrapper::printSectionsMapping(Executable::addr_type aType)
{
    std::map<offset_t, SectionHdrWrapper*> *secMap = NULL;

    if (aType == Executable::RAW) {
        secMap = &this->rSec;
    } else if (aType == Executable::RVA || aType == Executable::VA) {
        secMap = &this->vSec;
    }
    if (secMap == NULL) return;

    std::map<offset_t, SectionHdrWrapper*>::iterator itr;
    for (itr = secMap->begin(); itr != secMap->end(); itr++) {
        SectionHdrWrapper* sec = itr->second;
        offset_t secEnd = itr->first;

        printf("[%llX] %s %llX %llX\n", 
            static_cast<unsigned long long>(secEnd), 
            sec->getName().toStdString().c_str(), 
            static_cast<unsigned long long>(sec->getContentOffset(aType)), 
            static_cast<unsigned long long>(sec->getContentEndOffset(aType, true))
        );
    }
    printf("---\n\n");
}

