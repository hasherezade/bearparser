#include "pe/ClrDirWrapper.h"

/*
typedef struct IMAGE_COR20_HEADER
{
    // Header versioning
    DWORD                   cb;              
    WORD                    MajorRuntimeVersion;
    WORD                    MinorRuntimeVersion;

    // Symbol table and startup information
    IMAGE_DATA_DIRECTORY    MetaData;        
    DWORD                   Flags;           

    // The main program if it is an EXE (not used if a DLL?)
    // If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is not set, EntryPointToken represents a managed entrypoint.
    // If COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set, EntryPointRVA represents an RVA to a native entrypoint
    // (depricated for DLLs, use modules constructors intead). 
    union {
        DWORD               EntryPointToken;
        DWORD               EntryPointRVA;
    };

    // This is the blob of managed resources. Fetched using code:AssemblyNative.GetResource and
    // code:PEFile.GetResource and accessible from managed code from
    // System.Assembly.GetManifestResourceStream.  The meta data has a table that maps names to offsets into
    // this blob, so logically the blob is a set of resources. 
    IMAGE_DATA_DIRECTORY    Resources;
    // IL assemblies can be signed with a public-private key to validate who created it.  The signature goes
    // here if this feature is used. 
    IMAGE_DATA_DIRECTORY    StrongNameSignature;

    IMAGE_DATA_DIRECTORY    CodeManagerTable;           // Depricated, not used 
    // Used for manged codee that has unmaanaged code inside it (or exports methods as unmanaged entry points)
    IMAGE_DATA_DIRECTORY    VTableFixups;
    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

    // null for ordinary IL images.  NGEN images it points at a code:CORCOMPILE_HEADER structure
    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;

} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;
*/

pe::IMAGE_COR20_HEADER* ClrDirWrapper::clrDir()
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(pe::IMAGE_COR20_HEADER));
    if (ptr == NULL) return NULL;

    return (pe::IMAGE_COR20_HEADER*) ptr;
}

bool ClrDirWrapper::wrap()
{
    return true;
}

void* ClrDirWrapper::getPtr()
{
    return clrDir();
}

bufsize_t ClrDirWrapper::getSize()
{
    if (!getPtr()) return 0;
    return sizeof(pe::IMAGE_COR20_HEADER);
}

size_t ClrDirWrapper::getFieldsCount()
{
    if (!getPtr()) return 0;
    return FIELD_COUNTER;
}

QString ClrDirWrapper::getName()
{
    return "CLR Directory";
}

void* ClrDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::IMAGE_COR20_HEADER* d = clrDir();
    if (!d) return NULL;

    switch (fId) { 
        case CB: return &d->cb;
        case MAJOR_RUNTIME_VER: return &d->MajorRuntimeVersion;
        case MINOR_RUNTIME_VER:  return &d->MinorRuntimeVersion;
        case META_DATA_VA: return &d->MetaData.VirtualAddress;
        case META_DATA_SIZE: return &d->MetaData.Size;     
        case FLAGS: return &d->Flags;
        case ENTRY_POINT:
        {
            return &d->EntryPointRVA;
        }
        case RESOURCES_VA: return &d->Resources.VirtualAddress;
        case RESOURCES_SIZE: return &d->Resources.Size;
        case STRONG_NAME_SIGNATURE_VA: return &d->StrongNameSignature.VirtualAddress;
        case STRONG_NAME_SIGNATURE_SIZE: return &d->StrongNameSignature.Size;
        case CODE_MANAGER_TABLE_VA: return &d->CodeManagerTable.VirtualAddress;
        case CODE_MANAGER_TABLE_SIZE: return &d->CodeManagerTable.Size;
        case VTABLE_FIXUPS_VA: return &d->VTableFixups.VirtualAddress;
        case VTABLE_FIXUPS_SIZE: return &d->VTableFixups.Size;
        case EXPORT_ADDR_TABLE_JMPS_VA: return &d->ExportAddressTableJumps.VirtualAddress;
        case EXPORT_ADDR_TABLE_JMPS_SIZE: return &d->ExportAddressTableJumps.Size;
        case MANAGED_NATIVE_HDR_VA: return &d->ManagedNativeHeader.VirtualAddress;
        case MANAGED_NATIVE_HDR_SIZE: return &d->ManagedNativeHeader.Size;
    }
    return this->getPtr();
}

QString ClrDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case CB: return "Cb";
        case MAJOR_RUNTIME_VER: return "MajorRuntimeVersion";
        case MINOR_RUNTIME_VER: return "MinorRuntimeVersion";
        case META_DATA_VA: return "MetaData.VA";
        case META_DATA_SIZE: return "MetaData.Size";
        case FLAGS: return "Flags";
        case ENTRY_POINT: {
            const pe::IMAGE_COR20_HEADER* d = clrDir();
            if (!d) return "EntryPoint";
            
            if (d->Flags & pe::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) {
                return "EntryPointRVA";
            } else {
                return "EntryPointToken";
            }
        }
        case RESOURCES_VA: return "Resources.VA";
        case RESOURCES_SIZE: return "Resources.Size";
        case STRONG_NAME_SIGNATURE_VA: return "StrongNameSignature.VA";
        case STRONG_NAME_SIGNATURE_SIZE: return "StrongNameSignature.Size";
        case CODE_MANAGER_TABLE_VA: return "CodeManagerTable.VA";
        case CODE_MANAGER_TABLE_SIZE: return "CodeManagerTable.Size";
        case VTABLE_FIXUPS_VA: return "VTableFixups.VA";
        case VTABLE_FIXUPS_SIZE: return "VTableFixups.Size";
        case EXPORT_ADDR_TABLE_JMPS_VA: return "ExportAddressTableJumps.VA";
        case EXPORT_ADDR_TABLE_JMPS_SIZE: return "ExportAddressTableJumps.Size";
        case MANAGED_NATIVE_HDR_VA: return "ManagedNativeHeader.VA";
        case MANAGED_NATIVE_HDR_SIZE: return "ManagedNativeHeader.Size";
    }
    return getName();
}

Executable::addr_type ClrDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case ENTRY_POINT: {
            const pe::IMAGE_COR20_HEADER* d = clrDir();
            if (!d) return Executable::NOT_ADDR;
            if (d->Flags & pe::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) {
                return Executable::RVA;
            } else {
                return Executable::NOT_ADDR;
            }
        }
        case RESOURCES_VA: 
        case META_DATA_VA:
        case STRONG_NAME_SIGNATURE_VA:
        case CODE_MANAGER_TABLE_VA: 
        case VTABLE_FIXUPS_VA: 
        case EXPORT_ADDR_TABLE_JMPS_VA: 
        case MANAGED_NATIVE_HDR_VA: 
            return Executable::RVA;
    }
    return Executable::NOT_ADDR;
}

std::set<DWORD> ClrDirWrapper::getFlagsSet(DWORD flags)
{
    const size_t clrFlagsCount = 6;
    const DWORD clrFlags[clrFlagsCount] = {
        pe::COMIMAGE_FLAGS_ILONLY,
        pe::COMIMAGE_FLAGS_32BITREQUIRED,
        pe::COMIMAGE_FLAGS_IL_LIBRARY,
        pe::COMIMAGE_FLAGS_STRONGNAMESIGNED,
        pe::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT,
        pe::COMIMAGE_FLAGS_TRACKDEBUGDATA
    }; 
    std::set<DWORD> allFlags;
    for (size_t i = 0; i < clrFlagsCount; ++i) {
        const DWORD nextFlag = clrFlags[i];
        if (flags & nextFlag) {
            allFlags.insert(nextFlag);
        }
    }
    return allFlags;
}

QString ClrDirWrapper::translateFlag(DWORD flags)
{
    if (flags & pe::COMIMAGE_FLAGS_ILONLY) {
        return ("IL Only");
    }
    if (flags & pe::COMIMAGE_FLAGS_32BITREQUIRED) {
        return("32-bit required");
    }
    if (flags & pe::COMIMAGE_FLAGS_IL_LIBRARY) {
        return ("IL Library");
    }
    if (flags & pe::COMIMAGE_FLAGS_STRONGNAMESIGNED) {
        return("Strong Name Signed");
    }
    if (flags & pe::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) {
        return("Native EntryPoint");
    }
    if (flags & pe::COMIMAGE_FLAGS_TRACKDEBUGDATA) {
        return("Track Debug Data");
    }
    return "";
}

QString ClrDirWrapper::translateFieldContent(size_t fieldId)
{
    const pe::IMAGE_COR20_HEADER* d = clrDir();
    if (!d) return "";
    
    if (fieldId != FLAGS) return "";
    
    std::set<DWORD> flagsSet = ClrDirWrapper::getFlagsSet(d->Flags);
    std::set<DWORD>::iterator itr;
    QStringList list;
    for (itr = flagsSet.begin() ; itr != flagsSet.end(); itr++) {
        const DWORD nextFlag = *itr;
        const QString flagInfo = ClrDirWrapper::translateFlag(nextFlag);
        if (flagInfo.length() == 0) continue;
        list.append(flagInfo);
    }
    return list.join(';');
}

