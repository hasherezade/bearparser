#include "PENodeWrapper.h"
#include "PEFile.h"

using namespace pe;

PEElementWrapper::PEElementWrapper(PEFile* pe)
    : ExeElementWrapper(pe), m_PE(pe)
{
}

//--------------------------------------------------------------------

PENodeWrapper::PENodeWrapper(PEFile *exe, PENodeWrapper* parent)
    : ExeNodeWrapper(exe, parent, 0), m_PE(exe), peParentNode(parent)
{
    wrap();
}

PENodeWrapper::PENodeWrapper(PEFile *exe, PENodeWrapper* parent, size_t entryNumber)
    : ExeNodeWrapper(exe, parent, entryNumber), m_PE(exe), peParentNode(parent)
{
    wrap();
}
