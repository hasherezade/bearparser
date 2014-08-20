#pragma once

#include "ExeCommander.h"


namespace cmd_util {
    void printResourceTypes(PEFile *pe);
    void printStrings(PEFile *pe, size_t limit);
    void dumpResourcesInfo(PEFile *pe, pe::resource_type type, size_t wrapperId);
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

class DumpLibCommand : public Command
{
public:
    DumpLibCommand(int v_wrapperId, std::string desc)
        : Command(desc), wrapperId(v_wrapperId) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        MappedExe* exe = dynamic_cast<MappedExe*>(cmd_util::getExeFromContext(context));
        ImportBaseDirWrapper* imps = dynamic_cast<ImportBaseDirWrapper*>(exe->getWrapper(wrapperId));
        if (imps == NULL) {
            std::cerr << "Invalid Wrapper" << std::endl;
            return;
        }
        cmd_util::dumpEntryInfo(imps);

        size_t num = 0;
        printf("lib Number: ");
        scanf("%d", &num);

        ExeNodeWrapper* lib = imps->getEntryAt(num);
        cmd_util::dumpEntryInfo(lib);
        cmd_util::dumpNodeInfo(lib);
    }

protected:
    int wrapperId; //TODO: fetch it from params!
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


