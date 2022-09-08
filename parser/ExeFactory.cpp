#include "ExeFactory.h"

#include "pe/DOSExe.h"
#include "pe/PEFile.h"

std::map<ExeFactory::exe_type, ExeBuilder*> ExeFactory::builders;

void ExeFactory::init()
{
    if (builders.size() > 0) {
        return; // already initialized
    }
    builders[MZ] = new DOSExeBuilder();
    builders[PE] = new PEFileBuilder();
}

void ExeFactory::destroy()
{
    std::map<exe_type, ExeBuilder*>::iterator itr;
    for (itr = builders.begin(); itr != builders.end(); itr++) {
        ExeBuilder* builder = itr->second;
        delete builder;
    }
    builders.clear();
}

ExeFactory::exe_type ExeFactory::findMatching(AbstractByteBuffer *buf)
{
    if (!buf) return NONE;
    
    ExeFactory::init(); //ensue that the builders are initialized

    std::map<exe_type, ExeBuilder*>::iterator itr;
    for (itr = builders.begin(); itr != builders.end(); itr++) {

        ExeBuilder* builder = itr->second;
        if (builder == NULL) continue;

        if (builder->signatureMatches(buf)) {
            return itr->first;
        }
    }
    return NONE;
}

Executable* ExeFactory::build(AbstractByteBuffer *buf, exe_type type)
{
    ExeFactory::init(); //ensue that the builders are initialized

    if (builders.find(type) == builders.end()) {
        return NULL;
    }
    ExeBuilder* builder = builders[type];
    if (!builder) return NULL;

    return builder->build(buf);
}

QString ExeFactory::getTypeName(exe_type type)
{
    ExeFactory::init(); //ensue that the builders are initialized

    if (builders.find(type) == builders.end()) return "Not supported";

    ExeBuilder* builder = builders[type];
    if (builder == NULL) return "Not supported";

    return builder->typeName();
}
