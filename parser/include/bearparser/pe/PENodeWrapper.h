#pragma once

#include "../ExeNodeWrapper.h"
#include "pe_formats.h"

class PEFile;

class PEElementWrapper : public ExeElementWrapper
{
public:
    PEElementWrapper(PEFile* pe);
    virtual ~PEElementWrapper() {}

    PEFile* getPE() { return m_PE; }

protected:
    PEFile *m_PE;

friend class PEFile;
};

//----

class PENodeWrapper : public ExeNodeWrapper
{
public:
    PENodeWrapper(PEFile* pe, PENodeWrapper* parent = NULL);
    PENodeWrapper(PEFile* pe, PENodeWrapper* parent, size_t entryNumber);

    virtual ~PENodeWrapper() {}

    PEFile* getPE() { return m_PE; }
    virtual PENodeWrapper* getParentNode() { return peParentNode; }

protected:
    PEFile *m_PE;
    PENodeWrapper *peParentNode;

friend class PEFile;
};
