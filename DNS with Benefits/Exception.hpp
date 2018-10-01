//
//  Exception.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 7/11/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef Exception_h
#define Exception_h

#include <exception>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <sstream>
#include <sys/errno.h>

class Exception : public std::exception
{
    std::string _msg;
    
public:
    Exception(const std::string& msg, int errnum = errno)
    {
        std::stringstream stream((std::string()));
        stream << "An Exception Happened!!!\n" << "Details: " << msg << std::endl;
        if (errnum)
            stream << "Error num: " << errnum << ", Description: " << strerror(errnum) << std::endl;
        _msg = stream.str();
    }
    
    virtual const char* what() const noexcept override
    {
        return _msg.c_str();
    }
};

#endif /* Exception_h */
