#pragma once

#include <stdio.h>
#include <iostream>
#include <string>
#include <map>

#include <bearparser/bearparser.h>

class Commander;

class CmdException : public CustomException
{
public:
    CmdException(const QString info) : CustomException(info) {}
};

class CmdParams
{
public:
    CmdParams() {}
    virtual ~CmdParams() {}
};

class CmdContext
{
public:
    CmdContext() : endProcessing(false) {}
    virtual ~CmdContext() {}
    void stopProcessing() { endProcessing = true; }
    bool isEndProcessing() { return endProcessing; }

protected:
    bool endProcessing;

friend class Commander;
};

class Command
{
public:
    Command(const std::string& v_desc) : desc(v_desc) {}
    virtual ~Command() {}

    virtual std::string getDescription() { return desc; }

    virtual void execute(CmdParams *params, CmdContext *context_ptr) = 0; // throws exceptions
    virtual CmdParams* fetchParams(std::string stream)// throws exception
    {
        return NULL; 
    } 

protected:
    std::string desc;
};

class QuitCommand : public Command
{
public:
    QuitCommand() : Command("Quit") {}

    virtual void execute(CmdParams *params, CmdContext *context_ptr)
    { 
        if (context_ptr == NULL) {
            return;
        }
        context_ptr->stopProcessing();
    }

};

class Commander
{
public:
    Commander(CmdContext *v_context);
    virtual ~Commander() { clearCommands(); }

    void printHelp();
    bool addCommand(const std::string& name, Command *cmd, bool overwrite = true);

    virtual void parseCommands(); // main loop

protected:
    Command* getCommand(const std::string& line);
    void clearCommands();

    std::map<std::string, Command*> cmds;
    CmdContext *context;
};

