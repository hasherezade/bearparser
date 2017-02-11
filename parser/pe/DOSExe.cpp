#include "DOSExe.h"


bool DOSExeBuilder::signatureMatches(AbstractByteBuffer *buf)
{
    if (buf == NULL) return false;

    WORD *magic = (WORD*) buf->getContentAt(0, sizeof(WORD));
    if (magic == NULL) return false;

    if ((*magic) == pe::S_DOS || (*magic) == pe::S_DOS2) {
        return true;
    }

    return false;
}

Executable* DOSExeBuilder::build(AbstractByteBuffer *buf)
{
    Executable *exe = NULL;
    if (signatureMatches(buf) == false) return NULL;

    try {
        exe = new DOSExe(buf);
    } catch (ExeException &e) {
        //
    }
    return exe;
}

//-------------------------------------------------------------

DOSExe::DOSExe(AbstractByteBuffer *v_buf)
    : MappedExe(v_buf, Executable::BITS_16), dosHdrWrapper(NULL)
{
    wrap(buf);
}

void DOSExe::wrap(AbstractByteBuffer *v_buf)
{
    this->dosHdrWrapper = new DosHdrWrapper(this);

    m_dosHdr = (IMAGE_DOS_HEADER*) getContentAt(0, sizeof(IMAGE_DOS_HEADER));
    if (m_dosHdr == NULL) throw ExeException("Could not Wrap!");

    WORD* magic = (WORD*) this->dosHdrWrapper->getFieldPtr(DosHdrWrapper::MAGIC);

    if (this->dosHdrWrapper->getPtr() == NULL || magic == NULL) {
        throw ExeException("Could not Wrap!");
    }

    if ((*magic) != pe::S_DOS && (*magic) != pe::S_DOS2) {
        Logger::append(Logger::D_WARNING, "It is not a DOS file!\n");
        throw ExeException("It is not a DOS file!");
    }
    this->wrappers[WR_DOS_HDR] = this->dosHdrWrapper;
}

offset_t DOSExe::peSignatureOffset()
{
    LONG* lfnew = (LONG*) this->dosHdrWrapper->getFieldPtr(DosHdrWrapper::LFNEW);
    if (lfnew == NULL) return 0;

    return static_cast<offset_t>(*lfnew);
}

