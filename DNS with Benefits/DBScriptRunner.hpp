//
//  DBScriptRunner.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/21/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBScriptRunner_hpp
#define DBScriptRunner_hpp

#include <string>

class DBScriptRunner
{
    std::string interpreter;
    std::string command_opt;
    std::string script;
    
    std::string script_output;
    std::string script_error;
    uint8_t return_code = -1;
    
    static constexpr size_t buffer_size = 4096;
    char buffer[buffer_size];
    uid_t getuid(const std::string &user_name);
    
public:
    DBScriptRunner(const std::string &script, const std::string &interpreter = "/bin/bash", const std::string &command_opt = "-c");
    void execute(const std::string &user_name = "nobody", bool capture_stderr = true);
    
    operator bool();
    const std::string &output();
    const std::string &error();
    uint8_t exit_code();
};

#endif /* DBScriptRunner_hpp */
