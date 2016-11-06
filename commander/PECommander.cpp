#include "PECommander.h"
#include "pe/rsrc/ResourceStringsWrapper.h"

using namespace std;

PEFile* cmd_util::getPEFromContext(CmdContext *ctx)
{
    Executable* exe =  cmd_util::getExeFromContext(ctx);
    PEFile *pe = dynamic_cast<PEFile*>(exe);
    if (!pe) {
        std::cerr << "It's not a PE file" << std::endl;
    }
    return pe;
}

void cmd_util::printSectionMapping(SectionHdrWrapper *sec, Executable::addr_type aType)
{
    if (sec == NULL) return;

    offset_t hdrStart = sec->getContentOffset(aType, false);
    bufsize_t hdrSize = sec->getContentSize(aType, false);

    offset_t start = sec->getContentOffset(aType, true);
    bufsize_t size = sec->getContentSize(aType, true);

    std::string typeStr = cmd_util::addrTypeToStr(aType);
    printf("[%s]\n",typeStr.c_str());
    printf(" ------------[In Hdr]------[Mapped]\n");
    printf(" Offset:  %10llX \t%10llX\n",
        static_cast<unsigned long long>(hdrStart),
        static_cast<unsigned long long>(start)
    );
    printf(" Size:    %10lX \t%10lX\n",
        static_cast<unsigned long>(hdrSize),
        static_cast<unsigned long>(size)
    );
    printf(" Scope:  [%10llX - %10llX], size = %lX\n",
        static_cast<unsigned long long>(start),
        static_cast<unsigned long long>(start + size),
        static_cast<unsigned long>(size)
    );
    printf(" \n");
}

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
            printf("[ERROR] Null wrapper!\n");
            continue;
        }
        size_t count = wrapper->getResStringsCount();

        for (int i = 0; i < count; i++) {
            if (limit != 0 && limCount >= limit) return;

            ResString *resStr = wrapper->getResStringAt(i);
            if (resStr != NULL) {
                printf("[%8llX] [%lu] %s\n",
                    static_cast<unsigned long long>(resStr->offset),
                    static_cast<unsigned long>(resStr->getSize()),
                    resStr->getQString().toStdString().c_str()
                );
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
    printf ("Found in Resources: %lu, wrappers: %lu\n",
        static_cast<unsigned long>(wrappers->entriesCount()),
        static_cast<unsigned long>(wrappersCount)
    );
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
        printf("[%lu] %s\n",
            static_cast<unsigned long>(i),
            entry->getName().toStdString().c_str()
        );
    }
}

//------------------------------------------
void PECommander::initCommands()
{
    //
    this->addCommand("secV", new SectionByAddrCommand(Executable::RVA, "Section by RVA"));
    this->addCommand("secR", new SectionByAddrCommand(Executable::RAW, "Section by RAW"));

    this->addCommand("rstrings", new PrintStringsCommand("Print Strings from resources"));
    this->addCommand("rsl", new PrintWrapperTypesCommand("List Resource Types"));
    this->addCommand("rs", new WrapperInfoCommand("Resource Info"));

    this->addCommand("dir_mv", new MoveDataDirEntryCommand("Move DataDirectory"));
    this->addCommand("secdump", new SectionDumpCommand("Dump chosen Section info"));
    this->addCommand("secfdump", new SectionDumpCommand("Dump chosen Section Content into a file", true));
}

