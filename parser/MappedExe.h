#pragma once
#include <map>

#include "Executable.h"
#include "ExeElementWrapper.h"

class ExeWrappersContainer
{
public:
    enum WRAPPERS {
        WR_NONE = size_t(-1),
        COUNT_WRAPPERS = 0
    };

    ExeWrappersContainer() { }
    virtual ~ExeWrappersContainer(void) { clearWrappers(); }

    virtual ExeElementWrapper* getWrapper(size_t wrapperId);

    size_t wrappersCount() { return wrappers.size(); }
    QString getWrapperName(size_t id);

protected:
    virtual void wrap(AbstractByteBuffer *v_buf) = 0;
    void clearWrappers();

    std::map<size_t, ExeElementWrapper*> wrappers;
};

class MappedExe : public Executable, public ExeWrappersContainer {
public:
    virtual void wrap() { return wrap(this->buf); }

protected:
    MappedExe(AbstractByteBuffer *v_buf, exe_bits v_bitMode)
        : Executable(v_buf, v_bitMode), ExeWrappersContainer() { }

    virtual ~MappedExe(void) { }

    virtual void wrap(AbstractByteBuffer *v_buf) = 0;
    virtual bool resize(bufsize_t newSize) 
    { 
        if (Executable::resize(newSize)) {
            wrap(); 
            printf("Resize and rewrap...");
            return true;
        }
        return false;
    }
};
