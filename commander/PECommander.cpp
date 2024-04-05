#include "PECommander.h"
#include <bearparser/pe.h>

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
    ResourcesContainer *allStrings = pe->getResourcesOfType(pe::RESTYPE_STRING);
    if (allStrings == NULL) return;

    size_t wrappersCount = allStrings->count();
    if (wrappersCount == 0) {
        std::cout <<"No Strings in Resources!\n";
        return;
    }

    size_t limCount = 0;
    for (size_t i = 0; i < wrappersCount; i++) {
        ResourceStringsWrapper* wrapper = dynamic_cast<ResourceStringsWrapper*>(allStrings->getWrapperAt(i));
        if (wrapper == NULL) {
            std::cout << "[ERROR] Null wrapper!\n";
            continue;
        }
        size_t count = wrapper->getResStringsCount();

        for (size_t j = 0; j < count; j++) {
            if (limit != 0 && limCount >= limit) return;

            ResString *resStr = wrapper->getResStringAt(j);
            if (resStr != NULL) {
                OUT_PADDED_OFFSET(std::cout, resStr->offset);
                std::cout << " [" << std::dec << resStr->getSize() << "]" << std::endl;
                std::cout << resStr->getQString().toStdString() << "\n";
                limCount++;
            }
        }
    }
    std::cout << std::endl;
}

void cmd_util::dumpResourcesInfo(PEFile *pe, pe::resource_type type, size_t wrapperId)
{
    ResourcesContainer* wrappers = pe->getResourcesOfType(type);

    if (wrappers == NULL || wrappers->count() == 0) {
        std::cout << "No such resource type" << std::endl;
        return;
    }
    size_t wrappersCount = wrappers->count();
    if (wrapperId >= wrappersCount) {
        return;
    }
    std::cout << "Found in Resources:"
        << std::dec << wrappers->entriesCount()
        << std::dec << wrappersCount
        << std::endl;

    ResourceContentWrapper* wrapper = wrappers->getWrapperAt(wrapperId);
    if (wrapper == NULL) {
        return;
    }
    cmd_util::dumpEntryInfo(wrapper);
    cmd_util::dumpNodeInfo(dynamic_cast<ExeNodeWrapper*>(wrapper));
}

void cmd_util::listDataDirs(PEFile *pe)
{
    DataDirWrapper *dDir = dynamic_cast<DataDirWrapper*>(pe->getWrapper(PEFile::WR_DATADIR));
    const int recordsCount = (dDir) ? dDir->getDirsCount() : 0;
    for (size_t i = 0 ; i < recordsCount; i++) {
        DataDirEntryWrapper* entry = pe->getDataDirEntry(pe::dir_entry(i));
        if (entry == NULL) {
            continue;
        }
        std::cout << "[" << i << "]"
            << entry->getName().toStdString()
            << std::endl;
    }
}

//------------------------------------------
void PECommander::initCommands()
{
    this->addCommand("secV", new SectionByAddrCommand(Executable::RVA, "Section by RVA"));
    this->addCommand("secR", new SectionByAddrCommand(Executable::RAW, "Section by RAW"));

    this->addCommand("rstrings", new PrintStringsCommand("Print Strings from resources"));
    this->addCommand("rsl", new PrintWrapperTypesCommand("List Resource Types"));
    this->addCommand("rs", new WrapperInfoCommand("Resource Info"));

    this->addCommand("dir_mv", new MoveDataDirEntryCommand("Move DataDirectory"));
    this->addCommand("secinfo", new SectionDumpCommand("Dump chosen Section info"));
    this->addCommand("secfdump", new SectionDumpCommand("Dump chosen Section Content into a file", true));
    
    this->addCommand("explist", new ExportsListCommand("List all exports"));
    this->addCommand("implist", new ImportsListCommand("List all imports"));
}

