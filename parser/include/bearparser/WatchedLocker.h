#pragma once

#include <iostream>
#include <QtCore>

class WatchedLocker : public QMutexLocker {
public:  
    WatchedLocker(QMutex *mutex, bool show = false, const char *func = nullptr)
        : QMutexLocker(mutex), showLock(show)
    {
        if (func) funcName = func;
        if (showLock) {
            std::cout << __FUNCTION__;
            if (funcName.length()) {
                std::cout << " : " << funcName;
            }
            std::cout << std::endl;
        }
    }
        
    ~WatchedLocker()
    {
        if (showLock) {
            std::cout << __FUNCTION__;
            if (funcName.length()) {
                std::cout << " : " << funcName;
            }
            std::cout << std::endl;
        }
    }
    
protected:
    std::string funcName;
    bool showLock;
};
