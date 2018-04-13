#include "ExeCommander.h"
#include "../parser/ExeNodeWrapper.h"
#include "../parser/Formatter.h"
#include "../parser/FileBuffer.h"

//------------------------------------------

char cmd_util::addrTypeToChar(Executable::addr_type type)
{
    switch (type) {
        case Executable::RAW: return 'r';
        case Executable::RVA: return 'v';
        case Executable::VA: return 'V';
        default:
            return '_';
    }
    return '_';
}

std::string cmd_util::addrTypeToStr(Executable::addr_type type)
{
    switch (type) {
        case Executable::RAW: return "raw";
        case Executable::RVA: return "RVA";
        case Executable::VA: return "VA";
        default:
            return "";
    }
    return "";
}

Executable* cmd_util::getExeFromContext(CmdContext *context)
{
    ExeCmdContext *exeContext = dynamic_cast<ExeCmdContext*>(context);
    if (exeContext == NULL) throw CustomException("Invalid command context!");

    Executable *exe = exeContext->getExe();
    if (exe == NULL) throw CustomException("Invalid command context: no Exe");
    return exe;
}

offset_t cmd_util::readOffset(Executable::addr_type aType)
{
    if (aType == Executable::NOT_ADDR) {
        return INVALID_ADDR;
    }
    std::string prompt = addrTypeToStr(aType);
    offset_t offset = 0;
    std::cout << prompt.c_str() << ": ";
    std::cin >> std::hex >> offset;
    return offset;
}

size_t cmd_util::readNumber(std::string prompt, bool read_hex)
{
    unsigned int num = 0;
    std::cout << prompt.c_str() << ": ";
    if (read_hex) {
        std::cin >> std::hex >> num;
    } else {
        std::cin >> std::dec >> num;
    }
    return num;
}

void cmd_util::fetch(Executable *peExe, offset_t offset, Executable::addr_type aType, bool hex)
{
    offset = peExe->toRaw(offset, aType);
    if (offset == INVALID_ADDR) {
        std::cerr << "ERROR: Invalid Address suplied" << std::endl;
        return;
    }

    BufferView *sub = new BufferView(peExe, offset, 100);

    if (sub->getContent() == nullptr) {
        std::cout << "[ERROR] Cannot fetch" << std::endl;
        delete sub;
        return;
    }

    AbstractFormatter *formatter = nullptr;
    std::string separator = " ";

    if (hex) formatter = new HexFormatter(sub);
    else {
            formatter = new Formatter(sub);
            separator = "";
    }
    std::cout << "Fetched:" << std::endl;
    for (bufsize_t i = 0; i < sub->getContentSize(); i++) {
        std::cout << (*formatter)[i].toStdString() << separator.c_str();
    }
    std::cout << std::endl;

    delete formatter;
    delete sub;
}

void cmd_util::printWrapperNames(MappedExe *exe)
{
    size_t count = exe->wrappersCount();
    for (size_t i = 0; i < count; i++) {
        ExeElementWrapper *wr = exe->getWrapper(i);
        if (wr == NULL || wr->getPtr() == NULL) {
            continue;
        }
        std::cout << "[" << std::dec << i << "] ";
        std::cout << exe->getWrapperName(i).toStdString() << std::endl;
    }
}

void cmd_util::dumpEntryInfo(ExeElementWrapper *w)
{
    if (w == nullptr) return;
    
    std::cout << "\n------\n";
    size_t fields = w->getFieldsCount();
    
    std::cout << "[" << w->getName().toStdString() << "] ";
    std::cout << "size: ";
    
    OUT_PADDED_HEX(std::cout, w->getSize(), sizeof(bufsize_t));
    std::cout << " ";
    std::cout << "fieldsCount: " << std::dec << fields << "\n" << std::endl;

    for (int i = 0; i < fields; i++) {
        offset_t offset = w->getFieldOffset(i);
        if (offset == INVALID_ADDR) {
            continue;
        }
        OUT_PADDED_OFFSET(std::cout, offset);
        std::cout << " " << w->getFieldName(i).toStdString() << "\t";

        QString translated = w->translateFieldContent(i);
        if (translated.size() > 0) {
            std::cout << " " << translated.toStdString() << " ";
        }

        size_t subfields = w->getSubFieldsCount();
        for (size_t y = 0; y < subfields; y++) {
            WrappedValue value = w->getWrappedValue(i, y);
            QString str = value.toQString();

            Executable::addr_type aType = w->containsAddrType(i, y);
            char c = addrTypeToChar(aType);
            std::cout << "[" << str.toStdString() << " " << c << "]";
        }
        std::cout << "\n";
    }
    std::cout << "------" << std::endl;
}

void cmd_util::dumpNodeInfo(ExeNodeWrapper *w)
{
    if (w == nullptr) return;
    
    std::cout << "------" << std::endl;
    size_t entriesCnt = w->getEntriesCount();
    std::cout << "\t [" << w->getName().toStdString() << "] "
        << "entriesCount: " << std::dec << entriesCnt << std::endl;

    for (size_t i = 0; i < entriesCnt; i++) {
        ExeNodeWrapper* entry = w->getEntryAt(i);
        if (entry == NULL) break;
        
        std::cout << "Entry #" << std::dec << i << "\n";
        dumpEntryInfo(entry);
        size_t subEntries = entry->getEntriesCount();
        if (subEntries > 0) {
            std::cout << "Have entries: " 
            << std::dec << subEntries
            << " ( "
            << std::hex << "0x" << subEntries 
            << " )";
        }
        std::cout << "\n";
    }
}

void ExeCommander::initCommands()
{
    this->addCommand("info", new ExeInfoCommand());

    this->addCommand("r-v", new ConvertAddrCommand(Executable::RAW, Executable::RVA, "Convert: RAW -> RVA"));
    this->addCommand("v-r", new ConvertAddrCommand(Executable::RVA, Executable::RAW, "Convert: RVA -> RAW"));

    this->addCommand("printc", new FetchCommand(false, Executable::RAW, "Print content by Raw address"));
    //this->addCommand("cV", new FetchCommand(false, Executable::RVA, "Fetch content by Virtual address"));

    this->addCommand("printx", new FetchCommand(true, Executable::RAW, "Print content by Raw address - HEX"));
    //this->addCommand("hV", new FetchCommand(true, Executable::RVA, "Fetch content by Virtual address - HEX"));

    this->addCommand("cl", new ClearWrapperCommand("Clear chosen wrapper Content"));
    this->addCommand("fdump", new DumpWrapperToFileCommand("Dump chosen wrapper Content into a file"));
    this->addCommand("winfo", new DumpWrapperCommand("Dump chosen wrapper info"));
    this->addCommand("einfo", new DumpWrapperEntriesCommand("Dump wrapper entries"));

    this->addCommand("e_add", new AddEntryCommand("Add entry to a wrapper"));
    this->addCommand("save", new SaveExeToFileCommand());
}

//---

void ConvertAddrCommand::execute(CmdParams *params, CmdContext  *context)
{
    Executable *exe = cmd_util::getExeFromContext(context);
    offset_t offset = cmd_util::readOffset(addrFrom);

    offset_t outOffset = exe->convertAddr(offset, addrFrom, addrTo);
    if (outOffset == INVALID_ADDR) {
        std::cerr << "[WARNING] This address cannot be mapped" << std::endl;
        return;
    }
    std::cout << "[" << cmd_util::addrTypeToStr(addrFrom) << "]";
    std::cout << "\t->\t";
    std::cout << "[" << cmd_util::addrTypeToStr(addrTo) << "]";
    std::cout << ":\n";
    OUT_PADDED_OFFSET(std::cout, offset);
    std::cout << "\t->\t";
    OUT_PADDED_OFFSET(std::cout, outOffset);
    std::cout << std::endl;
}
//---

void ExeInfoCommand::execute(CmdParams *params, CmdContext  *context)
{
    Executable *exe = cmd_util::getExeFromContext(context);
    std::cout << "Bit mode: \t" << std::dec << exe->getBitMode() << "\n";
    
    offset_t entryPoint = exe->getEntryPoint();
    
    std::cout << "Entry point: \t";
    std::cout << "[";
    OUT_PADDED_OFFSET(std::cout, entryPoint);
    std::cout << " " << cmd_util::addrTypeToChar(Executable::RVA);
    std::cout << "]\n";
//Raw:
    std::cout << "Raw size: \t";
    OUT_PADDED_OFFSET(std::cout, exe->getMappedSize(Executable::RAW));
    std::cout << "\n";
    std::cout << "Raw align. \t";
    OUT_PADDED_OFFSET(std::cout, exe->getAlignment(Executable::RAW));
    std::cout << "\n";
//Virtual:
    std::cout << "Virtual size: \t";
    OUT_PADDED_OFFSET(std::cout, exe->getMappedSize(Executable::RVA));
    std::cout << "\n";
    std::cout << "Virtual align. \t";
    OUT_PADDED_OFFSET(std::cout, exe->getAlignment(Executable::RVA));
    std::cout << "\n";
    
    MappedExe *mappedExe = cmd_util::getMappedExeFromContext(context);
    if (mappedExe) {
        std::cout << "Contains:\n";
        cmd_util::printWrapperNames(mappedExe);
    }
    std::cout << std::endl;
}