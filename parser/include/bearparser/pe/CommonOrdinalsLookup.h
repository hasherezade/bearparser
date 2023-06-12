#pragma once

#include <QtCore>
#include "lookup/CommonOrdinalsMap.h"
#include "lookup/CommonOrdinalsWS2_32.h"
#include "lookup/CommonOrdinalsOleaut32.h"

class CommonOrdinalsLookup
{
public:
    CommonOrdinalsLookup()
    {
        init();
    }
    
    QString findFuncName(QString dllName, int ordinal)
    {
        dllName = dllName.toLower();
        
        if (!listsMap.contains(dllName)) {
            return QString();
        }
        
        CommonOrdinalsMap* ordinalsMap = listsMap[dllName];
        if (!ordinalsMap || !ordinalsMap->ord_names.contains(ordinal)) {
            return QString();
        } 
        return ordinalsMap->ord_names[ordinal];
    }
    
    void init()
    {
        listsMap["wsock32"] = new CommonOrdinalsWS2_32();
        listsMap["ws2_32"] = new CommonOrdinalsWS2_32();
        listsMap["oleaut32"] = new CommonOrdinalsOleaut32();
    }
    
    void clear()
    {
        for (auto itr = listsMap.begin(); itr != listsMap.end(); ++itr) {
            delete itr.value();
        }
        listsMap.clear();
    }
    
protected:
    QMap<QString, CommonOrdinalsMap*> listsMap;
};
