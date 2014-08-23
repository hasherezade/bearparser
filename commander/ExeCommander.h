#pragma once

#include "Commander.h"

namespace cmd_util {

    Executable* getExeFromContext(CmdContext *ctx);
    inline MappedExe* getMappedExeFromContext(CmdContext *ctx) { return dynamic_cast<MappedExe*>(getExeFromContext(ctx)); }

    char addrTypeToChar(Executable::addr_type type);

    offset_t readOffset(Executable::addr_type aType);
    size_t readNumber(std::string prompt);

    void fetch(Executable *exe, offset_t offset, Executable::addr_type aType, bool hex);
    void printWrapperNames(MappedExe *exe);

    void dumpEntryInfo(ExeElementWrapper *w);
    void dumpNodeInfo(ExeNodeWrapper *w);
};


class ExeCmdContext : public CmdContext
{
public:
    ExeCmdContext() : exe(NULL) {}
    void setExe(Executable *v_exe) { this->exe = v_exe; }
    Executable* getExe() { return this->exe; }

protected:
    Executable *exe;
};


class ExeCommander : public Commander
{
public:
    ExeCommander(ExeCmdContext *v_context)
        : Commander(v_context), exeContext(v_context)
    {
        initCommands();
    }

    void setExe(Executable *exe) { exeContext->setExe(exe); }

protected:
    virtual void initCommands();
    ExeCmdContext* exeContext;
};

class ConvertAddrCommand : public Command
{
public:
    ConvertAddrCommand(Executable::addr_type v_from, Executable::addr_type v_to, std::string desc)
        : Command(desc), addrFrom(v_from), addrTo(v_to) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        Executable *exe = cmd_util::getExeFromContext(context);
        offset_t offset = cmd_util::readOffset(addrFrom);

        offset_t outOffset = exe->convertAddr(offset, addrFrom, addrTo);
        printf("%llx -> %llx\n", offset, outOffset);
    }

protected:
    Executable::addr_type addrFrom;
    Executable::addr_type addrTo;
};

class FetchCommand : public Command
{
public:
    FetchCommand(bool v_isHex, Executable::addr_type v_addrType, std::string desc)
        : Command(desc), isHex(v_isHex), addrType(v_addrType) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        Executable *exe = cmd_util::getExeFromContext(context);
        offset_t offset = cmd_util::readOffset(addrType);
        cmd_util::fetch(exe, offset, addrType, isHex);
    }

protected:
    Executable::addr_type addrType;
    bool isHex;
};

class ExeInfoCommand : public Command
{
public:
    ExeInfoCommand(std::string desc = "Exe Info")
        : Command(desc) {}

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        Executable *exe = cmd_util::getExeFromContext(context);
        printf("Bit mode: \t%d\n", exe->getBitMode());
        printf("Entry point: \t%#llx%c\n", exe->getEntryPoint(), cmd_util::addrTypeToChar(Executable::RVA));
        printf("Raw size: \t%#lx\n", exe->getMappedSize(Executable::RAW));
        printf("Virtual size: \t%#lx\n", exe->getMappedSize(Executable::RVA));

        printf("Raw align.: \t%#lx\n", exe->getAlignment(Executable::RAW));
        printf("Virtual align.:\t%#lx\n", exe->getAlignment(Executable::RVA));
        MappedExe *mappedExe = cmd_util::getMappedExeFromContext(context);
        if (mappedExe) {
            printf("Contains:\n");
            cmd_util::printWrapperNames(mappedExe);
        }
    }
};

class WrapperCommand : public Command
{
public:
    WrapperCommand(std::string desc, int v_wrapperId = -1)
        : Command(desc), wrapperId(v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper) = 0;

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        MappedExe *mappedExe = cmd_util::getMappedExeFromContext(context);
        if (mappedExe == NULL) return;

        int wrId = wrapperId;
        if (wrId == -1) {
            cmd_util::printWrapperNames(mappedExe);
            wrId = cmd_util::readNumber("wrapperNum");
        }
        ExeElementWrapper *wrapper = mappedExe->getWrapper(wrId);
        if (wrapper == NULL) {
            printf("No such wrapper!\n");
            return;
        }
        wrapperAction(wrapper);
    }
protected:
    int wrapperId; //TODO: fetch it from params!
};

class AddEntryCommand : public WrapperCommand
{
public:
    AddEntryCommand(std::string desc, int v_wrapperId = -1)
        : WrapperCommand(desc, v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) {
            std::cerr << "Invalid Wrapper" << std::endl;
            return;
        }
        ExeNodeWrapper* nWrapper = dynamic_cast<ExeNodeWrapper*>(wrapper);
        if (nWrapper == NULL) {
            std::cerr << "This wrapper stores no entries!" << std::endl;
            return;
        }
        if (nWrapper->canAddEntry() == false) {
            std::cout << "No space to add entry" << std::endl;
            return;
        }
        if (nWrapper->addEntry(NULL)) {
            std::cout << "Added!" << std::endl;
            return;
        }
        std::cout << "Failed!" << endl;
    }
};

class DumpWrapperCommand : public WrapperCommand
{
public:
    DumpWrapperCommand(std::string desc, int v_wrapperId = -1)
        : WrapperCommand(desc, v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) return;
        cmd_util::dumpEntryInfo(wrapper);
        cmd_util::dumpNodeInfo(dynamic_cast<ExeNodeWrapper*>(wrapper));
    }
};

class DumpWrapperEntriesCommand : public WrapperCommand
{
public:
    DumpWrapperEntriesCommand(std::string desc, int v_wrapperId = -1)
        : WrapperCommand(desc), wrapperId(v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) {
            std::cerr << "Invalid Wrapper" << std::endl;
            return;
        }
        ExeNodeWrapper* nWrapper = dynamic_cast<ExeNodeWrapper*>(wrapper);
        if (nWrapper == NULL) {
            std::cerr << "This wrapper have no entries!" << std::endl;
            return;
        }

        cmd_util::dumpEntryInfo(nWrapper);

        size_t num = 0;
        printf("Dump subentries of Index: ");
        scanf("%d", &num);

        ExeNodeWrapper* lib = nWrapper->getEntryAt(num);
        cmd_util::dumpEntryInfo(lib);
        cmd_util::dumpNodeInfo(lib);
    }

protected:
    int wrapperId; //TODO: fetch it from params!
};


class ClearWrapperCommand : public WrapperCommand
{
public:
    ClearWrapperCommand(std::string desc, int v_wrapperId = -1)
        : WrapperCommand(desc, v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) return;
        BYTE filling = 0;
        if (wrapper->fillContent(filling)) {
            printf("Filled!\n");
        } else {
            printf("Failed to fill...\n");
        }
    }
};

class DumpWrapperToFileCommand : public WrapperCommand
{
public:
    DumpWrapperToFileCommand(std::string desc, int v_wrapperId = -1)
        : WrapperCommand(desc, v_wrapperId)
    {
        fileName = "dumped.txt";
    }

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        bufsize_t dSize = FileBuffer::dump(fileName, *wrapper, true);
        printf("Dumped size: %ld into: %s\n", dSize, fileName.toStdString().c_str());
    }
protected:
    QString fileName;
};

