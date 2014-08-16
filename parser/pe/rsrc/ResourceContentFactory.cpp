#include "ResourceContentFactory.h"
#include "ResourceStringsWrapper.h"
#include "ResourceVersionWrapper.h"

using namespace pe;

ResourceContentWrapper* ResourceContentFactory::makeResContentWrapper(pe::resource_type typeId, ResourceLeafWrapper* leaf)
{
    if (leaf == NULL) return NULL;

    Executable *pe = leaf->getExe();
    if (pe == NULL) return NULL;

    ResourceContentWrapper* cw = NULL;

    switch (typeId) {
        case pe::RT_STRING:
            cw = new ResourceStringsWrapper(pe, leaf);
            break;
        case pe::RT_VERSION:
            cw = new ResourceVersionWrapper(pe, leaf);
            break;
        default:
            cw = new ResourceContentWrapper(pe, leaf, typeId);
    }
    //printf("Making ResourceContentWrapper of type: %d\n", typeId);
    //if (!isSupportedType(typeId))
    return cw;
}
