#pragma once
#include "pe_formats.h"
#include "../ExeElementWrapper.h"


/*
typedef struct WIN_CERTIFICATE {
  DWORD dwLength;
  WORD wRevision;
  WORD wCertificateType;
  BYTE bCertificate[];
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
*/

class SecurityDirWrapper : public ExeElementWrapper
{
public:

    enum SecurityDirFID {
        NONE = FIELD_NONE,
        CERT_LEN = 0,
        REVISION,
        TYPE,
        CERT_CONTENT,
        FIELD_COUNTER
    };

    SecurityDirWrapper(Executable *pe);
    ~SecurityDirWrapper() { clear(); }

    bool wrap();

    virtual void* getPtr();

    virtual bufsize_t getSize();
    virtual QString getName() { return "Security"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);

    QString translateType(int type);

private:
    pe::WIN_CERTIFICATE* getCert();
    void clear() {}

    bool sizeOk;
};
