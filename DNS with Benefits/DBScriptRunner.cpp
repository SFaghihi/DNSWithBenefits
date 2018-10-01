//
//  DBScriptRunner.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/21/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBScriptRunner.hpp"

#include <iostream>
#include <sstream>

#include <sys/errno.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pwd.h>

extern char * const *environ;

/************************** Start of DBReadBuffer *****************************/

// Private
uid_t DBScriptRunner::getuid(const std::string &user_name)
{
    long bufsize;
    
    if ((bufsize = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1)
        return -1;
    
    char buffer[bufsize];
    struct passwd pwd, *result = NULL;
    if (getpwnam_r(user_name.c_str(), &pwd, buffer, bufsize, &result) != 0 || !result)
        return -1;
    
    return pwd.pw_uid;
}

// Constructor
DBScriptRunner::DBScriptRunner(const std::string &script, const std::string &interpreter, const std::string &command_opt)
: script(script), interpreter(interpreter), command_opt(command_opt)
{}

// Public
void DBScriptRunner::execute(const std::string &user_name, bool capture_stderr)
{
    uid_t new_uid = getuid(user_name);
    if (new_uid == -1)
    {
        script_error += "Couldn't find uid for '" + user_name + "'!!!\n";
        return;
    }
    
    int p_out[2], p_err[2];
    
    if (pipe(p_out))
    {
        script_error += "Error -> pIpEs!/!?A(out): ";
        script_error.append(strerror(errno));
        script_error += "\n";
        return;
    }
    
    if (capture_stderr)
    {
        if (pipe(p_err))
        {
            script_error += "Error -> pIpEs!/!?A(err): ";
            script_error.append(strerror(errno));
            script_error += "\n";
            return;
        }
    }
    
    pid_t child = fork();
    if (child == -1)
    {
        script_error += "Error -> fOrK!/!?A(err): ";
        script_error.append(strerror(errno));
        script_error += "\n";
        close(p_out[0]); close(p_out[1]);
        if (capture_stderr) { close(p_err[0]); close(p_err[1]); }
        return;
    }
    
    if (child == 0)
    {
        // Become the user_name
        if (setuid(new_uid))
        {
            if (capture_stderr)
                perror("sEtUiD!/!?A");
            exit(-1);
        }
        
        if (!capture_stderr)
            dup2(open("/dev/null", O_WRONLY), STDERR_FILENO);
        else {
            dup2(p_err[1], STDERR_FILENO); close(p_err[0]);
        }
        dup2(p_out[1], STDOUT_FILENO); close(p_out[0]);
        
        const char * const argvs[4] = {
            interpreter.c_str(),
            command_opt.c_str(),
            script.c_str(),
            nullptr
        };
        
        if (execve("/bin/bash", (char * const *)argvs, environ))
        {
            perror("execve!/!?A");
            exit(-2);
        }
    }
    
    close(p_out[1]); if (capture_stderr) close(p_err[1]);
    int child_stat = 0;
    std::ostringstream output_stream;
    std::ostringstream error_stream;
    int poll_fd_num = capture_stderr ? 2 : 1;
    pollfd pollfds[poll_fd_num];
    {
        pollfds[0].fd = p_out[0];
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
    }
    if (capture_stderr)
    {
        pollfds[1].fd = p_err[0];
        pollfds[1].events = POLLIN;
        pollfds[1].revents = 0;
    }
    
    while (!waitpid(child, &child_stat, WNOHANG))
    {
        {
            pollfds[0].fd = p_out[0];
            pollfds[0].events = POLLIN;
            pollfds[0].revents = 0;
        }
        if (capture_stderr)
        {
            pollfds[1].fd = p_err[0];
            pollfds[1].events = POLLIN;
            pollfds[1].revents = 0;
        }
        
        if (poll(pollfds, poll_fd_num, -1) <= 0)
        {
            script_error += "Error -> pOlL?!2c: ";
            script_error.append(strerror(errno));
            script_error += "\n";
            
            sleep(1);
            if (!waitpid(child, &child_stat, WNOHANG))
            {
                kill(child, SIGKILL);
                waitpid(child, &child_stat, 0);
            }
            if (WIFEXITED(child_stat))
            {
                return_code = WEXITSTATUS(child_stat);
                script_output += output_stream.str();
                script_error += error_stream.str();
                close(p_out[0]);
                if (capture_stderr) close(p_err[0]);
                return;
            }
        }
        
        for (int i = 0; i < poll_fd_num; i++)
        {
            if (pollfds[i].revents & POLLIN)
            {
                ssize_t read_len = read(pollfds[i].fd, buffer, buffer_size);
                if (read_len > 0)
                {
                    if (i == 0)
                        output_stream.write(buffer, read_len);
                    else
                        error_stream.write(buffer, read_len);
                }
            }
            else if (pollfds[i].revents)
            {
                script_error += "Error -> pOlL?!2c(revent): " + std::to_string(pollfds[i].revents);
                script_error.append(strerror(errno));
                script_error += "\n";
                
                sleep(1);
                if (!waitpid(child, &child_stat, WNOHANG))
                {
                    kill(child, SIGKILL);
                    waitpid(child, &child_stat, 0);
                }
                if (WIFEXITED(child_stat))
                {
                    return_code = WEXITSTATUS(child_stat);
                    script_output += output_stream.str();
                    script_error += error_stream.str();
                    close(p_out[0]);
                    if (capture_stderr) close(p_err[0]);
                    return;
                }
            }
        }
        
    }
    
    if (WIFEXITED(child_stat))
        return_code = WEXITSTATUS(child_stat);
        
    script_output += output_stream.str();
    script_error += error_stream.str();
        
    close(p_out[0]);
    if (capture_stderr) close(p_err[0]);
}


DBScriptRunner::operator bool()
{
    return !return_code && script_output.length();
}

uint8_t DBScriptRunner::exit_code()         { return return_code; }
const std::string &DBScriptRunner::error()  { return script_error; }
const std::string &DBScriptRunner::output() { return script_output; }


