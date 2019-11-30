#pragma once
#include "win_hdrs/win_types.h"

#include <exception>
#include <errno.h>
#include <QtCore>
#include <string>

#define UNKNOWN_EXCEPTION (-1)

class CustomException : public std::exception
{
public:
    CustomException(const QString info, const int32_t code = UNKNOWN_EXCEPTION)
        : std::exception(), m_info(info), m_code(code) { m_strInfo = info.toStdString(); }

    CustomException(const int32_t code)
        : std::exception(), m_info(""),  m_code(code) {}

    virtual ~CustomException() throw () {}

    QString getInfo() { return (m_info.length() > 0) ? m_info : codeToString(); }
    int getCode() { return m_code; }
    virtual const char *what() const throw() { return  m_strInfo.c_str(); }

protected:
    virtual QString codeToString() { return ""; } /* for inherited classes */
    QString m_info;
    std::string m_strInfo;
    const int m_code;
};

class ParserException : public CustomException
{
public:
    ParserException(const QString info) : CustomException(info) {}
};

