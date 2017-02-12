#include "SecurityDirWrapper.h"
#include "PEFile.h"

pe::WIN_CERTIFICATE* SecurityDirWrapper::getCert()
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RAW, sizeof(pe::WIN_CERTIFICATE));
    if (ptr == NULL) return NULL;

    return (pe::WIN_CERTIFICATE*) ptr;
}

bool SecurityDirWrapper::wrap()
{
    this->sizeOk = false;

    pe::WIN_CERTIFICATE* cert = getCert();
    if (cert == NULL) return false;

    offset_t offset = this->getFieldOffset(SecurityDirWrapper::CERT_CONTENT);
    if (offset == INVALID_ADDR) return false;
    BYTE *ptr = NULL;

    size_t fieldsSize = sizeof(cert->dwLength) + sizeof(cert->wRevision) + sizeof(cert->dwLength);
    size_t certSize = cert->dwLength - fieldsSize;
    ptr = m_Exe->getContentAt(offset, Executable::RAW, static_cast<bufsize_t>(certSize));

    if (ptr == NULL) return false;

    this->sizeOk = true;
    return true;
}

void* SecurityDirWrapper::getPtr()
{
    return getCert();
}

bufsize_t SecurityDirWrapper::getSize()
{
    pe::WIN_CERTIFICATE* cert = getCert();
    if (cert == NULL) return 0;

    bufsize_t fullSize = static_cast<bufsize_t>(sizeof(pe::WIN_CERTIFICATE)); // TODO: check it
    if (this->sizeOk) {
        fullSize = static_cast<bufsize_t>(cert->dwLength);
    }
    return fullSize;
}


void* SecurityDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::WIN_CERTIFICATE* cert = getCert();
    if (cert == NULL) return 0;

    switch (fId) {
        case CERT_LEN : return &cert->dwLength;
        case REVISION : return &cert->wRevision;
        case TYPE : return &cert->wCertificateType;
        case CERT_CONTENT : return &cert->bCertificate;
    }
    return this->getPtr();
}

QString SecurityDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case CERT_LEN : return "Length";
        case REVISION : return "Revision";
        case TYPE : return "Type";
        case CERT_CONTENT : return "Cert. Content";
    }
    return getName();
}

WrappedValue::data_type SecurityDirWrapper::containsDataType(size_t fieldId, size_t subField)
{
    if (fieldId == CERT_CONTENT){
        return WrappedValue::COMPLEX;
    }
    return WrappedValue::INT;
}

QString SecurityDirWrapper::translateType(int type)
{
    switch (type) {
        case pe::WIN_CERT_TYPE_X509  : return "X.509 certificate";
        case pe::WIN_CERT_TYPE_PKCS_SIGNED_DATA : return "PKCS Signed Data";
        case pe::WIN_CERT_TYPE_RESERVED_1 : return "Reserved";
        case pe::WIN_CERT_TYPE_PKCS1_SIGN : return "PKCS1 Module Sign Fields";
    }
    return "";
}

QString SecurityDirWrapper::translateFieldContent(size_t fieldId)
{
    if (fieldId != TYPE) return "";

    pe::WIN_CERTIFICATE* cert = getCert();
    if (cert == NULL) return "";

    return translateType(cert->wCertificateType);
}
