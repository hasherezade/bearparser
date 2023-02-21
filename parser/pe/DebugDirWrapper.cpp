#include "pe/DebugDirWrapper.h"
#include <QtGlobal>

using namespace pe;
/*
typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Type;
    DWORD   SizeOfData;
    DWORD   AddressOfRawData;
    DWORD   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

*/

bool DebugDirWrapper::loadNextEntry(size_t cntr)
{
    const size_t dirSize = this->getSize();
    const size_t entriesCount = dirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
    if (cntr >= entriesCount) {
        return false;
    }

    DebugDirEntryWrapper* dbgEntry = new DebugDirEntryWrapper(m_PE, this, cntr);
    if (!dbgEntry || !dbgEntry->getPtr()) {
        delete dbgEntry;
        return false;
    }
    entries.push_back(dbgEntry);
    return true;
}

//---

bool DebugDirEntryWrapper::wrap()
{
    if (this->getDebugStruct()) {
        DebugDirCVEntryWrapper *cvWrapper = new DebugDirCVEntryWrapper(m_Exe, this);
        this->entries.push_back(cvWrapper);
    }
    return true;
}

void* DebugDirEntryWrapper::getPtr()
{
    return debugDir();
}

bufsize_t DebugDirEntryWrapper::getSize()
{
    if (!getPtr()) return 0;
    return sizeof(IMAGE_DEBUG_DIRECTORY);
}

void* DebugDirEntryWrapper::getFieldPtr(size_t fId, size_t subField)
{
    IMAGE_DEBUG_DIRECTORY* d = debugDir();
    if (d == NULL) return NULL;

    switch (fId) {
        case CHARACTERISTIC: return &d->Characteristics;
        case TIMESTAMP: return &d->TimeDateStamp;
        case MAJOR_VER: return &d->MajorVersion;
        case MINOR_VER: return &d->MinorVersion;
        case TYPE: return &d->Type;
        case DATA_SIZE: return &d->SizeOfData;
        case RAW_DATA_ADDR: return &d->AddressOfRawData;
        case RAW_DATA_PTR: return &d->PointerToRawData;
    }
    return this->getPtr();
}

QString DebugDirEntryWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case CHARACTERISTIC: return "Characteristics";
        case TIMESTAMP: return "TimeDateStamp";
        case MAJOR_VER: return "MajorVersion";
        case MINOR_VER: return "MinorVersion";
        case TYPE: return "Type";
        case DATA_SIZE: return "SizeOfData";
        case RAW_DATA_ADDR: return "AddressOfRawData";
        case RAW_DATA_PTR: return "PointerToRawData";
    }
    return getName();
}

Executable::addr_type DebugDirEntryWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case RAW_DATA_ADDR: return Executable::RVA;
        case RAW_DATA_PTR: return Executable::RAW;
    }
    return Executable::NOT_ADDR;
}

QString DebugDirEntryWrapper::translateType(int type)
{
    switch (type) {
        case pe::DT_UNKNOWN : return "unknown";
        case pe::DT_COFF : return "COFF";
        case pe::DT_CODEVIEW : return "Visual C++ (CodeView)";
        case pe::DT_FPO : return "Frame pointer omission";
        case pe::DT_MISC : return "DBG file";
        case pe::DT_EXCEPTION : return "A copy of .pdata section";
        case pe::DT_FIXUP : return "Reserved";
        case pe::DT_OMAP_TO_SRC : return "mapping from an RVA in image to an RVA in source image";
        case pe::DT_OMAP_FROM_SRC : return "mapping from an RVA in source image to an RVA in image";
        case pe::DT_BORLAND : return "Borland";
        case pe::DT_RESERVED10 : return "Reserved";
        case pe::DT_CLSID : return "CLSID";
        case pe::DT_VC_FEATURE : return "VC Feature";
        case pe::DT_POGO : return "POGO";
        case pe::DT_ILTCG : return "ILTCG";
        case pe::DT_MPX : return "MPX";
        case pe::DT_REPRO : return "REPRO";
    }
    return "<Unknown>";
}

QString DebugDirEntryWrapper::translateFieldContent(size_t fieldId)
{
    if (fieldId != TYPE) return "";

    IMAGE_DEBUG_DIRECTORY* d = debugDir();
    if (d == NULL) return NULL;

    return translateType(d->Type);
}

BYTE* DebugDirEntryWrapper::getDebugStruct()
{
    IMAGE_DEBUG_DIRECTORY* d = this->debugDir();
    if (d == NULL) return NULL;
    if (d->Type != DT_CODEVIEW) {
        return NULL;
    }
    offset_t rva = d->PointerToRawData;
    size_t dirSize = d->SizeOfData;
    return m_Exe->getContentAt(rva, Executable::RAW, dirSize);
}

DEBUG_RSDSI* DebugDirEntryWrapper::getRDSI()
{
    BYTE* debugStr = getDebugStruct();
    IMAGE_DEBUG_DIRECTORY* d = debugDir();
    if (!debugStr || !d) return NULL;
    if (d->SizeOfData < sizeof(DEBUG_RSDSI)) {
        return NULL;
    }
    DEBUG_RSDSI* rdsi = (DEBUG_RSDSI*)debugStr;
    if (rdsi->dwSig == CV_SIGNATURE_RSDS) {
        return rdsi;
    }
    return NULL;
}

pe::DEBUG_NB10* DebugDirEntryWrapper::getNB10()
{
    BYTE* debugStr = getDebugStruct();
    IMAGE_DEBUG_DIRECTORY* d = debugDir();
    if (!debugStr || !d) return NULL;
    if (d->SizeOfData < sizeof(DEBUG_NB10)) {
        return NULL;
    }
    DEBUG_NB10* nb = (DEBUG_NB10*)debugStr;
    if (nb->cvHdr.CvSignature == CV_SIGNATURE_NB10) {
        return nb;
    }
    return NULL;
}
//-------------------------

void* DebugDirCVEntryWrapper::getPtr()
{
    DEBUG_RSDSI* rdsi = parentDir->getRDSI();
    if (rdsi) {
        return rdsi;
    }
    return parentDir->getNB10();
}

bufsize_t DebugDirCVEntryWrapper::getSize()
{
    IMAGE_DEBUG_DIRECTORY* d = parentDir->debugDir();
    if (d == NULL) return 0;
    return d->SizeOfData;
}

void* DebugDirCVEntryWrapper::getFieldPtr(size_t fId, size_t subField)
{
    DEBUG_RSDSI* rdsi = parentDir->getRDSI();
    if (rdsi) {
        switch (fId) {
        case F_CVDBG_SIGN: return &rdsi->dwSig;
        case F_CVDBG_GUID: return &rdsi->guidSig;
        case F_CVDBG_AGE: return &rdsi->age;
        case F_CVDBG_PDB: return &rdsi->szPdb;
        }
        return rdsi;
    }
    DEBUG_NB10* dbg = parentDir->getNB10();
    if (dbg) {
        switch (fId) {
        case F_CVDBG_SIGN: return &dbg->cvHdr.CvSignature;
        case F_CVDBG_GUID: return &dbg->Signature;
        case F_CVDBG_AGE: return &dbg->Age;
        case F_CVDBG_PDB: return &dbg->PdbFileName;
        }
        return dbg;
    }
    return NULL;
}

QString DebugDirCVEntryWrapper::getGuidString()
{
    DEBUG_RSDSI* rdsi = parentDir->getRDSI();
    if (rdsi) {
        QString chunk4 = "";
        for (size_t i = 0; i < sizeof(rdsi->guidSig.Data4); i++) {
            QString out;
#if QT_VERSION >= 0x050000
            out = QString().asprintf("%02X", rdsi->guidSig.Data4[i]);
#else
            out = QString().sprintf("%02X", rdsi->guidSig.Data4[i]);
#endif
            chunk4 += out;
        }
        QString chunk5 = "";
        for (size_t i = 0; i < sizeof(rdsi->guidSig.Data5); i++) {
            QString out;
#if QT_VERSION >= 0x050000
            out = QString().asprintf("%02X", rdsi->guidSig.Data5[i]);
#else
            out = QString().sprintf("%02X", rdsi->guidSig.Data5[i]);
#endif
            chunk5 += out;
        }
        QString out;
#if QT_VERSION >= 0x050000
        out = QString().asprintf("%08X-%04X-%04X-",
            rdsi->guidSig.Data1,
            rdsi->guidSig.Data2,
            rdsi->guidSig.Data3);
#else
        out = QString().sprintf("%08X-%04X-%04X-",
            rdsi->guidSig.Data1,
            rdsi->guidSig.Data2,
            rdsi->guidSig.Data3);
#endif
        return "{" + out + chunk4 + "-" + chunk5 + "}";
    }

    DEBUG_NB10* dbg = parentDir->getNB10();
    if (dbg) {
        QString out;
#if QT_VERSION >= 0x050000
        out = QString().asprintf("%04X", dbg->Signature);
#else
        out = QString().sprintf("%04X", dbg->Signature);
#endif
        return out;
    }
    return "";
}

QString DebugDirCVEntryWrapper::getSignature()
{
    DEBUG_RSDSI* rdsi = (DEBUG_RSDSI*)this->getPtr();
    if (!rdsi) return "";

    QString out;
#if QT_VERSION >= 0x050000
    out = QString().asprintf("%.4s", (char*)&rdsi->dwSig);
#else
    out = QString().sprintf("%.4s", (char*)&rdsi->dwSig);
#endif
    return out;
}

QString DebugDirCVEntryWrapper::getFieldName(size_t fId)
{
    switch (fId) {
        case F_CVDBG_SIGN: return "CvSig";
        case F_CVDBG_GUID: return "Signature";
        case F_CVDBG_AGE: return "Age";
        case F_CVDBG_PDB: return "PDB";
    }
    return "";
}

QString DebugDirCVEntryWrapper::translateFieldContent(size_t fId)
{
    DEBUG_RSDSI* rdsi = parentDir->getRDSI();
    DEBUG_NB10* dbg = parentDir->getNB10();
    if (!rdsi && !dbg) return "";

    char *pdb = NULL;
    if (rdsi) pdb = (char*)rdsi->szPdb;
    if (dbg) pdb = (char*)dbg->PdbFileName;

    switch (fId) {
        case F_CVDBG_SIGN: return getSignature();
        case F_CVDBG_GUID: return getGuidString();
        case F_CVDBG_PDB: return pdb ? pdb : "";
    }
    return "";
}
