#pragma once

#include "ExeCommander.h"

namespace cmd_util {
    PEFile* getPEFromContext(CmdContext *ctx);
    void printSectionMapping(SectionHdrWrapper *sec, Executable::addr_type aType);
    void printResourceTypes(PEFile *pe);
    void printStrings(PEFile *pe, size_t limit);
    void dumpResourcesInfo(PEFile *pe, pe::resource_type type, size_t wrapperId);
    void listDataDirs(PEFile *pe);
};

//----------------------------------------------

class PECommander : public ExeCommander
{
public:
    PECommander(ExeCmdContext *v_context)
        : ExeCommander(v_context)
    {
        initCommands();
    }

protected:
    virtual void initCommands();
};

class SectionByAddrCommand : public Command
{
public:
    SectionByAddrCommand(Executable::addr_type v_addrType, std::string desc)
        : Command(desc), addrType(v_addrType) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        PEFile *peExe = cmd_util::getPEFromContext(context);
        if (!peExe) return;

        offset_t offset = cmd_util::readOffset(addrType);

        SectionHdrWrapper* sec = peExe->getSecHdrAtOffset(offset, addrType, true, true);
        if (sec == NULL) {
            printf("NOT found addr [0x%llX] in any section!\n", 
                static_cast<unsigned long long>(offset)
            );
            printf("----------------------------\n");
            return;
        }
        offset_t delta = offset - sec->getContentOffset(addrType);
        printf("Found addr [0x%llX] in section:\n",
            static_cast<unsigned long long>(offset)
        );
        printf("F: %8llX\n",
            static_cast<unsigned long long>(offset)
        );
        printf("offset from the sec. bgn: %8llX\n",
            static_cast<unsigned long long>(delta)
        );
        printf ("V: %8llX - %8llX (%llX)\n",
            static_cast<unsigned long long>(sec->getContentOffset(Executable::RVA)),
            static_cast<unsigned long long>(sec->getContentEndOffset(Executable::RVA, false)),
            static_cast<unsigned long long>(sec->getContentEndOffset(Executable::RVA, true))
        );
        printf ("R: %8llX - %8llX (%llX)\n",
            static_cast<unsigned long long>(sec->getContentOffset(Executable::RAW)),
            static_cast<unsigned long long>(sec->getContentEndOffset(Executable::RAW, false)),
            static_cast<unsigned long long>(sec->getContentEndOffset(Executable::RAW, true))
        );

        cmd_util::dumpEntryInfo(sec);
        printf("----------------------------\n");
    }

protected:
    Executable::addr_type addrType;
};

class PrintStringsCommand : public Command
{
public:
    PrintStringsCommand(std::string desc)
        : Command(desc) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        PEFile *pe = cmd_util::getPEFromContext(context);
        if (!pe) return;

        ResourcesContainer* container = pe->getResourcesOfType(pe::RESTYPE_STRING);
        if (container == NULL) {
            printf("No such resource type!\n");
            return;
        }
        size_t max = container->entriesCount();
        printf("Total: %lu\n", static_cast<unsigned long>(max));
        size_t limit = 0;
        if (max > 100) {
            limit = cmd_util::readNumber("max");
        }

       cmd_util::printStrings(pe, limit);
    }
protected:
    int wrapperId; //TODO: fetch it from params!
};

class PrintWrapperTypesCommand : public Command
{
public:
    PrintWrapperTypesCommand(std::string desc)
        : Command(desc) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        PEFile *pe = cmd_util::getPEFromContext(context);
        if (!pe) return;
        ResourcesAlbum *album = pe->getResourcesAlbum();
        if (!album) return;

        cmd_util::printResourceTypes(pe);
    }
};

class WrapperInfoCommand : public Command
{
public:
    WrapperInfoCommand(std::string desc)
        : Command(desc) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        PEFile *pe = cmd_util::getPEFromContext(context);
        if (!pe) return;

        ResourcesAlbum *album = pe->getResourcesAlbum();
        if (album == NULL) return;

        size_t dirsCount =  album->dirsCount();
        if (dirsCount == 0) {
            printf("No resources!\n");
            return;
        }
        cmd_util::printResourceTypes(pe);

        pe::resource_type type = (pe::resource_type) cmd_util::readNumber("wrapper type");

        ResourcesContainer* wrappers = pe->getResourcesOfType(type);
        size_t wrappersCount = 0;
        if (wrappers == NULL || (wrappersCount = wrappers->count()) == 0) {
            printf("No such resource type!\n");
            return;
        }
        size_t wrapperIndx = 0;

        if (wrappersCount > 1) {
            printf("Wrappers count: %lu\n",
                static_cast<unsigned long>(wrappersCount)
            );
            wrapperIndx = cmd_util::readNumber("wrapperIndex");
        }
        cmd_util::dumpResourcesInfo(pe, type, wrapperIndx);
    }
};

class MoveDataDirEntryCommand : public Command
{
public:
    MoveDataDirEntryCommand(std::string desc)
        : Command(desc) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        PEFile *pe = cmd_util::getPEFromContext(context);
        if (!pe) return;

        printf("Available DataDirs: \n");
        cmd_util::listDataDirs(pe);

        pe::dir_entry entryId = static_cast<pe::dir_entry> (cmd_util::readNumber("DataDir id"));
        if (pe->getDataDirEntry(entryId) == NULL) {
            printf("No such wrapper\n");
            return;
        }

        offset_t offset = cmd_util::readOffset(Executable::RAW);
        try {
            if (pe->moveDataDirEntry(entryId, offset) == false) {
                printf("Failed\n");
                return;
            }
            printf("Done!\n");
        } catch (CustomException e){
            std::cerr << "[ERROR] "<< e.what() << std::endl;
        }
    }
};

class SectionDumpCommand : public Command
{
public:
    SectionDumpCommand(std::string desc, bool v_saveToFile = false)
        : Command(desc), saveToFile(v_saveToFile)
    {
        fileName = "sec_dump.txt";
    }

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        PEFile *pe = cmd_util::getPEFromContext(context);
        if (!pe) return;

        size_t sectHdrCount = pe->getSectionsCount(false);
        size_t sectCount = pe->getSectionsCount(true);
        printf("Sections count = %lu\n",
            static_cast<unsigned long>(sectCount)
        );
        if (sectCount == 0) {
            printf("No sections!\n");
            return;
        }
        printf("Available indexes: %lu-%lu\n", 0UL, static_cast<unsigned long>(sectCount - 1));
        size_t secId = cmd_util::readNumber("Chose the section by index");

        SectionHdrWrapper *sec = pe->getSecHdr(secId);
        if (sec == NULL) {
            printf("No such section\n");
            return;
        }
        Executable::addr_type aType = Executable::RAW;
        offset_t start = sec->getContentOffset(aType, true);
        bufsize_t size = sec->getContentSize(aType, true);

        printf("Section %s\n", sec->getName().toStdString().c_str());
        cmd_util::printSectionMapping(sec, Executable::RAW);
        cmd_util::printSectionMapping(sec, Executable::RVA);

        if (saveToFile) {
            BufferView *secView = pe->createSectionView(secId);
            if (secView == NULL) return;

            bufsize_t dSize = FileBuffer::dump(fileName, *secView, true);
            printf("Dumped size: %lu into: %s\n",
                static_cast<unsigned long>(dSize),
                fileName.toStdString().c_str()
            );
            delete secView;
        }
    }

protected:
    QString fileName;
    bool saveToFile;
};
