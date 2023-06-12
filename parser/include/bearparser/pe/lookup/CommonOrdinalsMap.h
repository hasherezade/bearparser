#pragma once

#include <QtCore>

class CommonOrdinalsMap
{
public:
    CommonOrdinalsMap()
        : dllName("") { }
    
    CommonOrdinalsMap(QString _dllName)
        : dllName(_dllName) { }
    
    QString dllName;
    QMap<int, QString> ord_names;
};
