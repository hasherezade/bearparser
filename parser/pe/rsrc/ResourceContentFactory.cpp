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
            return new ResourceStringsWrapper(pe, leaf);

        case pe::RT_VERSION: 
            return new ResourceVersionWrapper(pe, leaf);

        case pe::RT_MANIFEST:
            return new ReourceManifestWrapper(pe, leaf);

        case pe::RT_HTML:
            return new ReourceHTMLWrapper(pe, leaf);

        default:
            cw = new ResourceContentWrapper(pe, leaf, typeId);
    }
    //printf("Making ResourceContentWrapper of type: %d\n", typeId);
    //if (!isSupportedType(typeId))
    return cw;
}
