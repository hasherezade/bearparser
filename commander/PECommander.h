#pragma once

#include "ExeCommander.h"


namespace cmd_util {
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
        PEFile *peExe = dynamic_cast<PEFile*> (cmd_util::getExeFromContext(context));
        if (peExe == NULL) {
            std::cerr << "Invalid PEFile" << std::endl;
            return;
        }

        offset_t offset = cmd_util::readOffset(addrType);

        SectionHdrWrapper* sec = peExe->getSecHdrAtOffset(offset, addrType, true, true);
        if (sec == NULL) {
            printf("NOT found addr [0x%llX] in any section!\n", offset);
            printf("----------------------------\n");
            return;
        }
        offset_t delta = offset - sec->getContentOffset(addrType);
        printf("Found addr [0x%llX] in section:\n", offset);
        printf("F: %8llX\n", offset);
        printf("offset from the sec. bgn: %8llX\n", delta);
        printf ("V: %8llX - %8llX (%llX)\n",
            sec->getContentOffset(Executable::RVA),
            sec->getContentEndOffset(Executable::RVA, false),
            sec->getContentEndOffset(Executable::RVA, true)
        );
        printf ("R: %8llX - %8llX (%llX)\n",
            sec->getContentOffset(Executable::RAW),
            sec->getContentEndOffset(Executable::RAW, false),
            sec->getContentEndOffset(Executable::RAW, true)
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
        Executable *exe = cmd_util::getExeFromContext(context);
        PEFile *pe = dynamic_cast<PEFile*>(exe);
        ResourcesContainer* container = pe->getResourcesOfType(pe::RT_STRING);
        if (container == NULL) {
            printf("No such resource type!\n");
            return;
        }
        size_t max = container->entriesCount();
        printf("Total: %d\n", max);
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
        Executable *exe = cmd_util::getExeFromContext(context);
        PEFile *pe = dynamic_cast<PEFile*>(exe);
        ResourcesAlbum *album = pe->getResourcesAlbum();
        if (album == NULL) return;

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
        Executable *exe = cmd_util::getExeFromContext(context);
        PEFile *pe = dynamic_cast<PEFile*>(exe);
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
            printf("Wrappers count: %d\n", wrappersCount);
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
        Executable *exe = cmd_util::getExeFromContext(context);
        PEFile *pe = dynamic_cast<PEFile*>(exe);
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
    SectionDumpCommand(std::string desc)
        : Command(desc)
    {
        fileName = "sec_dump.txt";
    }

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        Executable *exe = cmd_util::getExeFromContext(context);
        PEFile *pe = dynamic_cast<PEFile*>(exe);
        if (!pe) return;

        size_t sectHdrCount = pe->getSectionsCount(false);
        size_t sectCount = pe->getSectionsCount(true);
        printf("Sections count = %d\n", sectCount);

        size_t secId = cmd_util::readNumber("chose the section by index:");

        SectionHdrWrapper *sec = pe->getSecHdr(secId);
        if (sec == NULL) {
            printf("No such section\n");
            return;
        }
        Executable::addr_type aType = Executable::RAW;
        offset_t hdrStart = sec->getContentOffset(aType, false);
        bufsize_t hdrSize = sec->getContentSize(aType, false);

        offset_t start = sec->getContentOffset(aType, true);
        bufsize_t size = sec->getContentSize(aType, true);

        printf("Section %s\n", sec->getName().toStdString().c_str());

        printf("In Hdr vs Mapped:\n");
        printf(" [RAW]\n Offset: %lld vs %lld\n Size:   %ld vs %ld\n", hdrStart, start, hdrSize, size);
        printf("RAW: [%lld - %lld], size = %ld\n", start, start + size, size);
        BufferView secView(pe,start,size);
        bufsize_t dSize = FileBuffer::dump(fileName, secView, true);
        printf("Dumped size: %ld into: %s\n", dSize, fileName.toStdString().c_str());
    }
protected:
    QString fileName;
};
