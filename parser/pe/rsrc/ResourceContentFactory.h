#pragma once

#include "ResourceContentWrapper.h"

class ResourceContentFactory
{
public:
    static ResourceContentWrapper *makeResContentWrapper(pe::resource_type typeId, ResourceLeafWrapper* leaf);
};

