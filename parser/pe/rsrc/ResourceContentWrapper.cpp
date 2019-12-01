#include "pe/rsrc/ResourceContentWrapper.h"

QString ResourceContentWrapper::translateType(pe::resource_type type)
{
    switch (type) {
        case pe::RESTYPE_CURSOR : return "Cursor";
        case pe::RESTYPE_FONT : return "Font";
        case pe::RESTYPE_BITMAP : return "Bitmap";
        case pe::RESTYPE_ICON : return "Icon";
        case pe::RESTYPE_MENU : return "Menu";
        case pe::RESTYPE_DIALOG : return "Dialog";
        case pe::RESTYPE_STRING : return "Strings";
        case pe::RESTYPE_FONTDIR : return "Font Dir.";
        case pe::RESTYPE_ACCELERATOR : return "Accelerator";
        case pe::RESTYPE_RCDATA : return "RC Data";
        case pe::RESTYPE_MESSAGETABLE : return "Message Table";

        case pe::RESTYPE_GROUP_CURSOR : return "Cursors Group";
        case pe::RESTYPE_GROUP_ICON : return "Icons Group";
        case pe::RESTYPE_VERSION : return "Version";
        case pe::RESTYPE_DLGINCLUDE : return "Dialog Include";
        case pe::RESTYPE_PLUGPLAY : return "Plug-n-Play";
        case pe::RESTYPE_VXD : return "VXD";
        case pe::RESTYPE_ANICURSOR : return "Animated Cursor";
        case pe::RESTYPE_ANIICON : return "Animated Icon";
        case pe::RESTYPE_HTML : return "HTML";
        case pe::RESTYPE_MANIFEST : return "Manifest";
    }
    return "UNKN";
}

//-------------------------------------------------------

void* ResourceContentWrapper::getResContentPtr()
{
    if (myLeaf == NULL) return NULL;

    IMAGE_RESOURCE_DATA_ENTRY* entry = this->myLeaf->leafEntryPtr();
    if (entry == NULL) return NULL;

    offset_t dataRva = static_cast<offset_t>(entry->OffsetToData);
    bufsize_t dataSize = static_cast<bufsize_t>(entry->Size);

    Executable* m_Exe = myLeaf->getExe();
    Executable::addr_type aT = m_Exe->detectAddrType(dataRva, Executable::RVA);
    offset_t dataOffset = m_Exe->toRaw(dataRva, aT);
    if (dataOffset == INVALID_ADDR) return NULL;

    BYTE* b = m_Exe->getContentAt(dataRva, aT, dataSize);
    return b;
}

bufsize_t ResourceContentWrapper::getResContentSize()
{
    if (myLeaf == NULL) {
        printf("[ERR] MyLeaf is NULL\n");
        return 0;
    }
    IMAGE_RESOURCE_DATA_ENTRY* entry = this->myLeaf->leafEntryPtr();
    if (entry == NULL) {
        printf("[ERR] Leaf ERR\n");
        return 0;
    }
    DWORD size = entry->Size;
    return size;
}

offset_t ResourceContentWrapper::getContentRaw()
{
    if (myLeaf == NULL) return 0;

    IMAGE_RESOURCE_DATA_ENTRY* entry = this->myLeaf->leafEntryPtr();
    if (entry == NULL) return 0;

    uint64_t dataRva = entry->OffsetToData;
    Executable* m_Exe = myLeaf->getExe();
    Executable::addr_type aT = m_Exe->detectAddrType(dataRva, Executable::RVA);
    return m_Exe->toRaw(dataRva, aT);
}

BYTE* ResourceContentWrapper::getContentAt(offset_t dataAddr, Executable::addr_type aT, bufsize_t dataSize)
{
    if (myLeaf == NULL) return NULL;

    Executable* m_Exe = myLeaf->getExe();
    BYTE* b = m_Exe->getContentAt(dataAddr, aT, dataSize);
    return b;
}

