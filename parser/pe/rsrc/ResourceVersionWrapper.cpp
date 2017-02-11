#include "ResourceVersionWrapper.h"

ResourceVersionWrapper::ResourceVersionWrapper(Executable *pe, ResourceLeafWrapper* v_leaf)
    : ResourceContentWrapper(pe, v_leaf, pe::RESTYPE_VERSION)
{
//TEST
/*    printf("Version: %s\n", getVersionText().toStdString().c_str());

    pe::version_info *info = getVersionInfo();
    if (info == NULL) return;

    if (info->children == 0) {
        printf("No children!");
        return;
    }
    BYTE *childEntry = (BYTE*) &info->children;
    pe::version_child* child = (pe::version_child*) m_Exe->getContentAtPtr(childEntry, sizeof(pe::version_child));
    if (child == NULL) {
        printf("[ERR] Cannot fetch a child\n");
    } else {
        printf("Got child of type: [%d]\n", child->wType);
         printf("len = %x\nValLen = %x\ntype = %x\nkey[0] = %c\n", child->wLength, child->wValueLength, child->wType, child->szKey[0]);

        int size = INFOTEXT_LEN;
        WORD *content = (WORD*) child->szKey;
        if (content == NULL) return;

        QString str = QString::fromUtf16(content, size);
        std::string verStr = str.toStdString();
        printf("key = [%s] len = %d\n", verStr.c_str(), verStr.length());
    }
    */
//!TEST
}

pe::version_info* ResourceVersionWrapper::getVersionInfo()
{
    void *ptr = this->getResContentPtr();
    if (ptr == NULL) return NULL;

    size_t size = this->getResContentSize();
    if (size < sizeof(pe::version_info)) return NULL;

    pe::version_info* info = (pe::version_info*) ptr;
    return info;
}

QString ResourceVersionWrapper::getFieldName(size_t fId)
{
    switch (fId) {
        case STRUCT_LEN: return "Length of Structure";
        case VAL_LEN: return "Length of Value";
        case STRUCT_TYPE: return "Type of Structure";
        case INFO: return "Info";
        //case PADDING1: return "Padding1";
        case SIGNATURE: return "Signature";
        case STRUCT_VER: return "Struct. Version";

        case FILE_VER_0:
        case FILE_VER_1: return "File Version";

        case PRODUCT_VER_0:
        case PRODUCT_VER_1: return "Product Version";

        case FLAGS_MASK: return "File Flags mask";
        case FLAGS: return "Flags";
        case OS: return "File OS";
        case TYPE: return "File Type";
        case SUBTYPE: return "File SubType";
        case TIMESTAMP_0: case TIMESTAMP_1: return "File Timestamp";
        //case PADDING2: return "Padding2";
        case CHILDREN: return "Children";
    }
    return "";
}

void* ResourceVersionWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::version_info* ptr = getVersionInfo();

    if (ptr == NULL) return NULL;

    switch (fId) {
        case STRUCT_LEN: return &(ptr->length);
        case VAL_LEN: return &(ptr->valueLength);
        case STRUCT_TYPE: return &(ptr->type);
        case INFO: return &(ptr->key);

        case SIGNATURE: return &(ptr->Value.dwSignature);
        case STRUCT_VER: return &(ptr->Value.dwStrucVersion);
        case FILE_VER_0: return &(ptr->Value.dwFileVersionMS);
        case FILE_VER_1: return &(ptr->Value.dwFileVersionLS);

        case PRODUCT_VER_0: return &(ptr->Value.dwProductVersionMS);
        case PRODUCT_VER_1: return &(ptr->Value.dwProductVersionLS);

        case FLAGS_MASK: return &(ptr->Value.dwFileFlagsMask);
        case FLAGS: return &(ptr->Value.dwFileFlags);
        case OS: return &(ptr->Value.dwFileOS);
        case TYPE: return &(ptr->Value.dwFileType);
        case SUBTYPE: return &(ptr->Value.dwFileSubtype);
        case TIMESTAMP_0: return &(ptr->Value.dwFileDateMS);
        case TIMESTAMP_1: return &(ptr->Value.dwFileDateLS);

        //case PADDING2: return &(ptr->padding2);
        case CHILDREN: return &(ptr->children);
    }
    return ptr;
}

WrappedValue::data_type ResourceVersionWrapper::containsDataType(size_t fieldId, size_t subField)
{
    if (fieldId == INFO) {
        return WrappedValue::WSTRING;
    }
    return WrappedValue::INT;
}