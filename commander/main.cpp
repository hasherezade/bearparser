#include <stdio.h>
#include <bearparser.h>

#include <iostream>
#include <QtCore>
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
    printf("Starting...\n");

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
        FileMap *fileMap = new FileMap(fName);
        ExeFactory::exe_type exeType = ExeFactory::findMatching(fileMap);

        if (exeType == ExeFactory::NONE) {
           fprintf(stderr, "Type not supported\n");
           ExeFactory::destroy();
           return 1;
        }
        printf("Type: %s\n", ExeFactory::getTypeName(exeType).toStdString().c_str());
        const bufsize_t MINBUF = 0x200;
        bufsize_t readableSize = fileMap->getContentSize();
        bufsize_t allocSize = (readableSize < MINBUF) ? MINBUF : readableSize;

        printf("Buffering...\n");
        ByteBuffer *buf= new ByteBuffer(fileMap, 0, allocSize);
        delete fileMap;

        printf("Parsing executable...\n");
        Executable *exe = ExeFactory::build(buf, exeType);

        exeContext.setExe(exe);
        commander.parseCommands();

        delete exe;
        delete buf;

    } catch (CustomException e) {
        fprintf(stderr, "[ERROR] %s\n", e.what());
    }
    printf("Done!\n");
    ExeFactory::destroy();
    return 0;
}

