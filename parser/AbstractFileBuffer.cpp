#include "AbstractFileBuffer.h"
#include <stdlib.h>

using namespace std;

#ifdef _WINDOWS
    char AbstractFileBuffer::PATH_SEPARATOR = WINDOWS_SEPARATOR;
#else
    char AbstractFileBuffer::PATH_SEPARATOR = UNIX_SEPARATOR;
#endif

//--------------------------------------------------

bool AbstractFileBuffer::dumpFragment(offset_t offset, bufsize_t size, QString path)
{
    BYTE *contentPart = this->getContentAt(offset, size);
    if (contentPart == NULL) return false;

    ByteBuffer partBuf(contentPart, size);
    return ByteBuffer::dumpToFile(path, partBuf);
}

