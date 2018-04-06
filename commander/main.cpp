#include <stdio.h>
#include <bearparser.h>

#include <iostream>
#include <QString>
#include <QtCore/QCoreApplication>

#include "PECommander.h"

#define TITLE "BearCommander"

using namespace std;

QString getFileName()
{
    QTextStream qtin(stdin, QIODevice::ReadOnly);
    QString fName;

    int trials = 3;
    do {
        printf("Path to executable: ");
        fName = qtin.readLine();
        if (QFile::exists(fName)) break;

        fprintf(stderr, "No such file! Remaining attempts: %d\n", trials);
        trials--;

    } while (trials);

    return fName;
}

int main(int argc, char *argv[])
{
    std::cout << "Bearparser version: " <<  BEARPARSER_VERSION << std::endl;
    QCoreApplication app(argc, argv);

    ExeFactory::init();
    ExeCmdContext exeContext;
    PECommander commander(&exeContext);

    QString fName;
    if (argc < 2) {
        fName = getFileName();
    } else {
        fName = QString(argv[1]);
    }
    try {
        FileView *fileView = NULL;
        bufsize_t maxMapSize = FILE_MAXSIZE;
        do {
            try {
                fileView = new FileView(fName, maxMapSize);
            
            } catch (BufferException &e1) {
                std::cerr << "[ERROR] " << e1.what() << std::endl;
                maxMapSize = cmd_util::readNumber("Try again with size (hex): ", true);
            }
        } while (fileView == NULL);

        ExeFactory::exe_type exeType = ExeFactory::findMatching(fileView);
        if (exeType == ExeFactory::NONE) {
           fprintf(stderr, "Type not supported\n");
           ExeFactory::destroy();
           return 1;
        }
        
        std::cout << "Type: " << ExeFactory::getTypeName(exeType).toStdString() << std::endl;
        const bufsize_t MINBUF = 0x200;
        bufsize_t readableSize = fileView->getContentSize();
        bufsize_t allocSize = (readableSize < MINBUF) ? MINBUF : readableSize;

        std::cerr << "Buffering..." << std::endl;
        ByteBuffer *buf = new ByteBuffer(fileView, 0, allocSize);
        delete fileView;

        std::cerr << "Parsing executable..." << std::endl;
        Executable *exe = ExeFactory::build(buf, exeType);

        exeContext.setExe(exe);
        commander.parseCommands();

        delete exe;
        delete buf;

    } catch (CustomException e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
    }
    std::cout << "Bye!" << std::endl;
    ExeFactory::destroy();
    return 0;
}

