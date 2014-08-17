#include <stdio.h>
#include <bearparser.h>

#include <QtGui>
#include <iostream>
#include "PECommander.h"

#define TITLE "BearCommander"
using namespace std;

QString getFileName(bool reading)
{
    QString filter = "All Files (*);;Applications (*.exe);;Libraries (*.dll);;Drivers (*.sys);;Screensavers (*.scr)";
    QFileDialog *dialog = new QFileDialog(NULL, "Open", QDir::homePath(), filter);

    QString fName = "";
    if (reading)
        fName = dialog->getOpenFileName(NULL, "Open", "", filter);
    else
        fName = dialog->getSaveFileName(NULL, "Save", "", filter);;

    if (fName.size() == 0) {
        printf("No file!");
        return "";
    }
    cout << "Chosen: " << fName.toStdString() << endl;
    delete dialog;
    return fName;
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    printf("Starting...\n");
    app.setApplicationName(TITLE);
    app.setQuitOnLastWindowClosed(false);

    ExeCmdContext exeContext;
    PECommander commander(&exeContext);

    QString fName;
    if (argc < 2) {
        fName = getFileName(true);
    } else {
        fName = QString(argv[1]);
    }
    try {
        const bufsize_t MINBUF = 0x200;
        printf("Buffering...\n");
        ByteBuffer* buf = FileBuffer::read(fName, MINBUF);

        printf("Parsing executable...\n");
        Executable *exe = NULL;

        PEFileBuilder builder;
        if (builder.signatureMatches(buf)) {

            exe = builder.build(buf);

            exeContext.setExe(exe);
            commander.parseCommands();
        }
        delete exe;
        delete buf;

    } catch (CustomException e) {
        QMessageBox::warning(NULL, "ERR", e.getInfo());
    }
    cout << "Done!"<< endl;
    //int ret = app.exec();
    return 0;
}

