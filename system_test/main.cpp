//
//  main.cpp
//  system_test
//
//  Created by Soroush Faghihi on 8/20/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include <iostream>
#include <sstream>

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/uio.h>

extern char * const *environ;

int main(int argc, const char * argv[])
{
    // insert code here...
    int p_out[2], p_in[2], p_err[2];
    
    if (pipe(p_out) || pipe(p_in) || pipe(p_err))
    {
        perror("pIpEs!/!?A");
        exit(-1);
    }
    
    pid_t child = fork();
    if (child == -1)
    {
        perror("fOrK!/!?A");
        exit(-2);
    }
    
    if (child == 0)
    {
        dup2(p_out[1], STDOUT_FILENO); dup2(p_in[0], STDIN_FILENO); dup2(p_err[1], STDERR_FILENO);
        close(p_out[0]); close(p_err[0]); close(p_in[1]);
        char * const argvs[4] = {
            "/bin/bash",
            "-c",
            "ifconfig|egrep -o '10.8.13.1|10.8.13.33|10.8.13.65'",
            nullptr
        };
        if (execve("/bin/bash", argvs, environ))
        {
            perror("fOrK!/!?A");
            exit(-2);
        }
    }
    
    close(p_out[1]); close(p_err[1]); close(p_in[0]);

    int child_stat = 0;
    int fd_other[3] = {
        p_in[1],
        STDOUT_FILENO,
        STDERR_FILENO
    };
    
    std::string out_str;
    std::string err_str;
    std::ostringstream os;
    std::ostringstream es;
    
    while (!waitpid(child, &child_stat, WNOHANG))
    {
        pollfd pollfds[3] = {
            {
                STDIN_FILENO,
                POLLIN,
                0
            },
            {
                p_out[0],
                POLLIN,
                0
            },
            {
                p_err[0],
                POLLIN,
                0
            }
        };
        if (poll(pollfds, 3, -1) <= 0)
        {
            perror("pOlL?!2c");
            kill(child, SIGKILL);
            waitpid(child, &child_stat, 0);
            if (WIFEXITED(child_stat))
                std::cout << "\nChild Exited with code: " << WEXITSTATUS(child_stat) << "\n";
            goto DONE;
        }
        
        const size_t buf_len = 4096;
        char buf[buf_len];
        for (int i = 0; i < 3; i++)
        {
            if (pollfds[i].revents & POLLIN)
            {
                ssize_t read_len = read(pollfds[i].fd, buf, buf_len);
                if (read_len > 0)
                {
                    if (i == 1)
                        os.write(buf, read_len);
                    else if (i == 2)
                        es.write(buf, read_len);
                }
            }
            else if (pollfds[i].revents)
            {
                perror("pOlL?!2c");
                kill(child, SIGKILL);
                waitpid(child, &child_stat, 0);
                if (WIFEXITED(child_stat))
                    std::cout << "\nChild Exited with code: " << WEXITSTATUS(child_stat) << "\n";
                goto DONE;
            }
        }
        
    }
    
    if (WIFEXITED(child_stat))
        std::cout << "\nChild Exited with code: " << WEXITSTATUS(child_stat) << "\n";
    
DONE:
    //system("ls");
    
    os.write("\0", 1); es.write("\0", 1);
    std::cout << "DONE!\n" << "STDOUT:\n" << os.str() << " : " << os.str().length() << "\nSTDERR:\n" << es.str() << "\n";
    while (1)
        sleep(1);
    
    return 0;
}
