#include "ExeCommander.h"
#include "../parser/ExeNodeWrapper.h"
#include "../parser/Formatter.h"
#include "../parser/FileBuffer.h"

using namespace std;

//------------------------------------------

char cmd_util::addrTypeToChar(Executable::addr_type type)
{
    switch (type) {
        case Executable::RAW: return 'r';
        case Executable::RVA: return 'v';
        case Executable::VA: return 'V';
    }
    return '_';
}

std::string cmd_util::addrTypeToStr(Executable::addr_type type)
{
    switch (type) {
        case Executable::RAW: return "raw";
        case Executable::RVA: return "RVA";
        case Executable::VA: return "VA";
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
    offset_t offset = 0;

    if (aType == Executable::NOT_ADDR) return INVALID_ADDR;
    std::string prompt = addrTypeToStr(aType);

    printf("%s: ", prompt.c_str());
    scanf("%llx", &offset);
    return offset;
}

size_t cmd_util::readNumber(std::string prompt)
{
    size_t num = 0;
    printf("%s: ", prompt.c_str());
    scanf("%d", &num);
    return num;
}

void cmd_util::fetch(Executable *peExe, offset_t offset, Executable::addr_type aType, bool hex)
{
    offset = peExe->toRaw(offset, aType);
    if (offset == INVALID_ADDR) {
        std::cerr << "ERROR: Invalid Address suplied" << endl;
        return;
    }

    BufferView *sub = new BufferView(peExe, offset, 100);

    if (sub->getContent() == NULL) {
        cout << "Cannot fetch" << endl;
        delete sub;
        return;
    }

    AbstractFormatter *formatter = NULL;
    std::string separator = " ";

    if (hex) formatter = new HexFormatter(sub);
    else {
            formatter = new Formatter(sub);
            separator = "";
    }
    cout << "Fetched:" << endl;
    for (bufsize_t i = 0; i < sub->getContentSize(); i++) {
        printf("%s%s", (*formatter)[i].toStdString().c_str(), separator.c_str());
    }
    putchar('\n');

    delete formatter;
    delete sub;
}

void cmd_util::printWrapperNames(MappedExe *exe) {
    size_t count = exe->wrappersCount();

    for (size_t i = 0; i < count; i++) {
        ExeElementWrapper *wr = exe->getWrapper(i);
        if (wr == NULL || wr->getPtr() == NULL) continue;
        printf("[%2d] %s\n", i, exe->getWrapperName(i).toStdString().c_str());
    }
}

void cmd_util::dumpEntryInfo(ExeElementWrapper *w)
{
    if (w == NULL) return;
    printf("------\n");
    size_t fields = w->getFieldsCount();
    printf("\t[%s] size: %#x fieldsCount: %d\n\n", w->getName().toStdString().c_str(), w->getSize(), fields);

    for (int i = 0; i < fields; i++) {
        offset_t offset = w->getFieldOffset(i);
        if (offset == INVALID_ADDR) continue;
        printf("[%04llX] %s :\t", offset, w->getFieldName(i).toStdString().c_str());

        QString translated = w->translateFieldContent(i);
        if (translated.size() > 0) {
            printf("%s\t", translated.toStdString().c_str());
        }

        size_t subfields = w->getSubFieldsCount();
        for (int y = 0; y < subfields; y++) {
            WrappedValue value = w->getWrappedValue(i, y);
            QString str = value.toQString();

            Executable::addr_type aType = w->containsAddrType(i, y);
            char c = addrTypeToChar(aType);
            printf("[%s %c] ", str.toStdString().c_str(), c );
        }
        printf("\n");
    }
    printf("------\n");
}

void cmd_util::dumpNodeInfo(ExeNodeWrapper *w)
{
    if (w == NULL) return;
    printf("------\n");
    size_t entriesCnt = w->getEntriesCount();
    printf("\t[%s] entriesCount: %d\n\n", w->getName().toStdString().c_str(), entriesCnt);

    for (int i = 0; i < entriesCnt; i++) {
        ExeNodeWrapper* entry = w->getEntryAt(i);
        if (entry == NULL) break;
        printf("Entry %d:\n", i);
        dumpEntryInfo(entry);
        size_t subEntries = entry->getEntriesCount();
        if (subEntries > 0) {
            printf("Have entries: %d\n" , subEntries);
        }
        printf("\n");
    }
    printf("------\n");
}

void ExeCommander::initCommands()
{
    this->addCommand("info", new ExeInfoCommand());

    this->addCommand("Rv", new ConvertAddrCommand(Executable::RAW, Executable::RVA, "Convert: RAW -> RVA"));
    this->addCommand("Vr", new ConvertAddrCommand(Executable::RVA, Executable::RAW, "Convert: RVA -> RAW"));

    this->addCommand("cR", new FetchCommand(false, Executable::RAW, "Fetch content by Raw address"));
    this->addCommand("cV", new FetchCommand(false, Executable::RVA, "Fetch content by Virtual address"));

    this->addCommand("hR", new FetchCommand(true, Executable::RAW, "Fetch content by Raw address - HEX"));
    this->addCommand("hV", new FetchCommand(true, Executable::RVA, "Fetch content by Virtual address - HEX"));

    this->addCommand("cl", new ClearWrapperCommand("Clear chosen wrapper"));
    this->addCommand("fdump", new DumpWrapperToFileCommand("Dump chosen wrapper into a file"));
    this->addCommand("dump", new DumpWrapperCommand("Dump chosen wrapper info"));
    this->addCommand("edump", new DumpWrapperEntriesCommand("Dump wrapper entries"));

    this->addCommand("e_add", new AddEntryCommand("Add entry to a wrapper"));
    this->addCommand("save", new SaveExeToFileCommand());
}

