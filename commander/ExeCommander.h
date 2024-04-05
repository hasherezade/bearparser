#pragma once

#include "Commander.h"

#include <sstream>
#include <iomanip>
#define OUT_PADDED_HEX(stream, val, field_size) std::cout.fill('0'); stream << std::hex << std::setw(field_size) << val;
#define OUT_HEX_FIELD(stream, val, field_size) std::cout.fill('0'); stream << "[" << std::hex << std::setw(field_size) << val << "]";
#define OUT_PADDED_OFFSET(stream, val) OUT_HEX_FIELD(stream,val, sizeof(offset_t));

#define INVALID_WRAPPER size_t(-1)

namespace cmd_util {

    Executable* getExeFromContext(CmdContext *ctx);
    inline MappedExe* getMappedExeFromContext(CmdContext *ctx) { return dynamic_cast<MappedExe*>(getExeFromContext(ctx)); }

    char addrTypeToChar(Executable::addr_type type);
    std::string addrTypeToStr(Executable::addr_type type);

    offset_t readOffset(Executable::addr_type aType);
    size_t readNumber(const std::string& prompt, bool read_hex=false);

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
    ConvertAddrCommand(Executable::addr_type v_from, Executable::addr_type v_to, const std::string& desc)
        : Command(desc), addrFrom(v_from), addrTo(v_to) {}

    virtual void execute(CmdParams *params, CmdContext  *context);

protected:
    Executable::addr_type addrFrom;
    Executable::addr_type addrTo;
};


class FetchCommand : public Command
{
public:
    FetchCommand(bool v_isHex, Executable::addr_type v_addrType, const std::string& desc)
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
    ExeInfoCommand(const std::string& desc = "Exe Info")
        : Command(desc) {}

    virtual void execute(CmdParams *params, CmdContext  *context);
};

class WrapperCommand : public Command
{
public:
    WrapperCommand(const std::string& desc, size_t v_wrapperId = INVALID_WRAPPER)
        : Command(desc), wrapperId(v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper) = 0;

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        MappedExe *mappedExe = cmd_util::getMappedExeFromContext(context);
        if (mappedExe == NULL) return;

        size_t wrId = wrapperId;
        if (wrId == INVALID_WRAPPER) {
            cmd_util::printWrapperNames(mappedExe);
            wrId = cmd_util::readNumber("wrapperNum", false);
        }
        ExeElementWrapper *wrapper = mappedExe->getWrapper(wrId);
        if (wrapper == NULL) {
            std::cout << "No such wrapper!" << std::endl;
            return;
        }
        wrapperAction(wrapper);
    }
protected:
    size_t wrapperId; //TODO: fetch it from params!
};

class AddEntryCommand : public WrapperCommand
{
public:
    AddEntryCommand(const std::string& desc, size_t v_wrapperId = INVALID_WRAPPER)
        : WrapperCommand(desc, v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) {
            std::cout << "Invalid Wrapper" << std::endl;
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
        std::cout << "Failed!" << std::endl;
    }
};

class DumpWrapperCommand : public WrapperCommand
{
public:
    DumpWrapperCommand(const std::string& desc, size_t v_wrapperId = INVALID_WRAPPER)
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
    DumpWrapperEntriesCommand(const std::string& desc, size_t v_wrapperId = INVALID_WRAPPER)
        : WrapperCommand(desc), wrapperId(v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) {
            std::cerr << "Invalid Wrapper" << std::endl;
            return;
        }
        ExeNodeWrapper* nWrapper = dynamic_cast<ExeNodeWrapper*>(wrapper);
        if (nWrapper == NULL) {
            std::cerr << "This wrapper has no entries!" << std::endl;
            return;
        }

        cmd_util::dumpEntryInfo(nWrapper);

        size_t num = cmd_util::readNumber("Dump subentries of Index: ");
        
        ExeNodeWrapper* lib = nWrapper->getEntryAt(num);
        cmd_util::dumpEntryInfo(lib);
        cmd_util::dumpNodeInfo(lib);
    }

protected:
    size_t wrapperId; //TODO: fetch it from params!
};


class ClearWrapperCommand : public WrapperCommand
{
public:
    ClearWrapperCommand(const std::string& desc, size_t v_wrapperId = INVALID_WRAPPER)
        : WrapperCommand(desc, v_wrapperId) {}

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (wrapper == NULL) return;
        BYTE filling = 0;
        if (wrapper->fillContent(filling)) {
            std::cout << "Filled!" << std::endl;
        } else {
            std::cout << "Failed to fill..." << std::endl;
            return;
        }
        MappedExe *mExe = dynamic_cast<MappedExe*>(wrapper->getExe());
        if (mExe) {
            mExe->wrap();
        }
    }
};

class DumpWrapperToFileCommand : public WrapperCommand
{
public:
    DumpWrapperToFileCommand(const std::string& desc, size_t v_wrapperId = INVALID_WRAPPER)
        : WrapperCommand(desc, v_wrapperId)
    {
    }

    virtual void wrapperAction(ExeElementWrapper *wrapper)
    {
        if (!wrapper) {
            return;
        }
        QString fileName = makeFileName(wrapper->getOffset());
        bufsize_t dSize = FileBuffer::dump(fileName, *wrapper, true);
        std::cout << "Dumped size: " << std::hex << "0x" << dSize 
            << " into: " << fileName.toStdString()
            << std::endl;
    }
    
protected:
    QString makeFileName(const offset_t wrapperOffset) 
    {
        std::stringstream sstr;
        sstr << "wrapper";
        if (wrapperOffset != INVALID_ADDR) {
            sstr << "_at_" << std::hex << wrapperOffset;
        }
        sstr << ".bin";
        return QString(sstr.str().c_str());
    }
};

class SaveExeToFileCommand : public Command
{
public:
    SaveExeToFileCommand(const std::string& desc = "Save exe to file")
        : Command(desc)
    {
    }

    virtual void execute(CmdParams *params, CmdContext  *context)
    {
        QString fileName = "dumped.exe";
        Executable *exe = cmd_util::getExeFromContext(context);

        bufsize_t dSize = FileBuffer::dump(fileName, *exe, true);
        std::cout << "Dumped size: " << std::hex << "0x" << dSize 
            << " into: " << fileName.toStdString()
            << std::endl;
    }
};
