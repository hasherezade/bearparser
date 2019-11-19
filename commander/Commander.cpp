#include "Commander.h"
#include <iostream>
#include <string>

using namespace std;

Commander::Commander(CmdContext *v_context)
    : context(v_context)
{
     if (this->context == NULL) throw CmdException("Uninitialized commander context!");
    addCommand("q", new QuitCommand());
}

void Commander::clearCommands()
{
    std::map<std::string, Command*>::iterator itr;
    for (itr = cmds.begin(); itr != cmds.end(); itr++) {
        Command* cmd = itr->second;
        delete cmd;
    }
    this->cmds.clear();
}

void Commander::printHelp()
{
    std::cout << "Available commands: " << cmds.size() << endl;
    std::map<std::string, Command*>::iterator itr;
    for (itr = cmds.begin(); itr != cmds.end(); itr++) {
        Command *cmd = itr->second;
        if (cmd == NULL) continue;
        std::cout << itr->first << " \t- " << cmd->getDescription() << endl;
    }
}

Command* Commander::getCommand(std::string line)
{
    std::string name = line;
    //TODO: split the line...
    if (cmds.find(name) == cmds.end() ) {
       std::cerr << "No such command" << endl;
       return NULL;
    }

    Command *cmd = this->cmds[name];
    return cmd;
}

bool Commander::addCommand(std::string name, Command *cmd, bool overwrite)
{
    if ( cmds.find(name) != cmds.end() ) {
        if (!overwrite) return false; // already exist
        delete this->cmds[name];
        this->cmds[name]  = NULL;
    }
    this->cmds[name] = cmd;
    return true;
}

void Commander::parseCommands()
{
    const std::string PROMPT = "$ ";
    Command *cmd = NULL;

    while (true) {
        if (this->context == NULL) throw CmdException("Uninitialized commander context!");
        if (this->context->isEndProcessing()) break;

        std::cout << PROMPT;
        std::string line;
        std::cin >> line;

        Command *cmd = getCommand(line);

        if (cmd == NULL) {
            this->printHelp();
            continue;
        }
        try {
            CmdParams *params = cmd->fetchParams(line);
            cmd->execute(params, this->context);
        } catch (CustomException &e) {
            std::cerr << "ERROR: " << e.what() << endl;
        }
    }
}

