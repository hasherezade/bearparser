#include "PECommander.h"
#include "pe/rsrc/ResourceStringsWrapper.h"

using namespace std;

void cmd_util::printResourceTypes(PEFile *pe)
{
    if (pe == NULL || pe->getResourcesAlbum() == NULL) return;
    ResourcesAlbum *album = pe->getResourcesAlbum();
    std::vector<pe::resource_type> types = album->getResourceTypes();
    for (size_t i = 0 ; i < types.size(); i++) {
        pe::resource_type type = types[i];
        QString info = ResourceContentWrapper::translateType(type);
        printf("[%3d]\t%s\n", type, info.toStdString().c_str());
    }
}

void cmd_util::printStrings(PEFile *pe, size_t limit)
{
    ResourcesContainer *allStrings = pe->getResourcesOfType(pe::RT_STRING);
    if (allStrings == NULL) return;

    size_t wrappersCount = allStrings->count();
    if (wrappersCount == 0) {
        printf ("No Strings in Resources!\n");
        return;
    }

    int limCount = 0;
    for (size_t i = 0; i < wrappersCount; i++) {
        ResourceStringsWrapper* wrapper = dynamic_cast<ResourceStringsWrapper*>(allStrings->getWrapperAt(i));
        if (wrapper == NULL) {
            printf("[ERR] Null wrapper!\n");
            continue;
        }
        size_t count = wrapper->getResStringsCount();

        for (int i = 0; i < count; i++) {
            if (limit != 0 && limCount >= limit) return;

            ResString *resStr = wrapper->getResStringAt(i);
            if (resStr != NULL) {
                printf("[%8llx] [%d] %s\n", resStr->offset, resStr->getSize(), resStr->getQString().toStdString().c_str());
                limCount++;
            }
        }
    }
}

void cmd_util::dumpResourcesInfo(PEFile *pe, pe::resource_type type, size_t wrapperId)
{
    ResourcesContainer* wrappers = pe->getResourcesOfType(type);

    if (wrappers == NULL || wrappers->count() == 0) {
        printf ("No such resource type\n");
        return;
    }
    size_t wrappersCount = wrappers->count();
    printf ("Found in Resources: %d, wrappers: %d\n", wrappers->entriesCount(), wrappersCount);
    int limCount = 0;
    std::vector<ResourceContentWrapper*>::iterator itr;
    if (wrapperId >= wrappersCount) return;

    ResourceContentWrapper* wrapper = wrappers->getWrapperAt(wrapperId);
    cmd_util::dumpEntryInfo(wrapper);
    cmd_util::dumpNodeInfo(dynamic_cast<ExeNodeWrapper*>(wrapper));
}

void cmd_util::listDataDirs(PEFile *pe)
{
    for (size_t i = 0 ; i < pe::DIR_ENTRIES_COUNT; i++) {
        DataDirEntryWrapper* entry = pe->getDataDirEntry(pe::dir_entry(i));
        if (entry == NULL) continue;
        printf("[%d] %s\n", i, entry->getName().toStdString().c_str());
    }
}

//------------------------------------------
void PECommander::initCommands()
{
    //
    this->addCommand("secV", new SectionByAddrCommand(Executable::RVA, "Section by RVA"));
    this->addCommand("secR", new SectionByAddrCommand(Executable::RAW, "Section by RAW"));

    this->addCommand("rstrings", new PrintStringsCommand("Print Strings from resources"));
    this->addCommand("rsrcs", new PrintWrapperTypesCommand("List Resource Types"));
    this->addCommand("rs", new WrapperInfoCommand("Resource Info"));

    this->addCommand("dir_mv", new MoveDataDirEntryCommand("Move DataDirectory"));
}

