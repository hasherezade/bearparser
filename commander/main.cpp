#include <stdio.h>
#include <bearparser/bearparser.h>

#include <iostream>
#include <QString>
#include <QtCore/QCoreApplication>

#include "PECommander.h"

#define TITLE "BearCommander"
#define MINBUF 0x200

using namespace std;

FileView* tryLoading(QString &fName)
{
    FileView *fileView = NULL;
    bufsize_t maxMapSize = FILE_MAXSIZE;
    do {
        if (!QFile::exists(fName)) {
            std::cerr << "[ERROR] " << "The file does not exist" << std::endl;
            break;
        }
        try {
            fileView = new FileView(fName, maxMapSize);
        } catch (BufferException &e1) {
            std::cerr << "[ERROR] " << e1.what() << std::endl;
            maxMapSize = static_cast<bufsize_t>(cmd_util::readNumber("Try again with size (hex): ", true));
            if (maxMapSize == 0) break;
        }
    } while (!fileView);
    
    return fileView;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    ExeFactory::init();
    ExeCmdContext exeContext;
    PECommander commander(&exeContext);

    if (argc < 2) {
        std::cout << "Bearparser version: " <<  BEARPARSER_VERSION << "\n";
        std::cout << "Args: <PE file>\n";
        commander.printHelp();
        return 0;
    }

    int status = 0;
    QString fName = QString(argv[1]);
    
    try {
        FileView* fileView = tryLoading(fName);
        if (!fileView) return -1;

        ExeFactory::exe_type exeType = ExeFactory::findMatching(fileView);
        if (exeType == ExeFactory::NONE) {
           std::cerr << "Type not supported\n";
           ExeFactory::destroy();
           return 1;
        }
        
        std::cout << "Type: " << ExeFactory::getTypeName(exeType).toStdString() << std::endl;
        bufsize_t readableSize = fileView->getContentSize();
        bufsize_t allocSize = (readableSize < MINBUF) ? MINBUF : readableSize;

        std::cout << "Buffering..." << std::endl;
        ByteBuffer *buf = new ByteBuffer(fileView, 0, allocSize);
        delete fileView; fileView = NULL; //the view is no longer needed

        std::cout << "Parsing executable..." << std::endl;
        Executable *exe = ExeFactory::build(buf, exeType);

        exeContext.setExe(exe);
        commander.parseCommands();

        delete exe;
        delete buf;
		
		std::cout << "Bye!" << std::endl;
		
    } catch (CustomException &e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
		status = -1;
    }
    ExeFactory::destroy();
    return status;
}

