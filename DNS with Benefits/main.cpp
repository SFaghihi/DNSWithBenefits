//
//  main.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/26/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include <iostream>

#include <arpa/inet.h>
#include <sys/time.h>

#include "cxxopts.hpp"

#include "DBRoutingSystem.hpp"
#include "DBDNSHypervisor.hpp"

// Cammand line options structure
struct CMDOpt {
public:
    const char *listen_host;
    int listen_port;
    bool verbose;
    const char *conf_file;
    
    CMDOpt(int argc, const char *argv[])
    : listen_host("127.0.0.1"), listen_port(53), verbose(false), conf_file("")
    {

    }
    
    void usage()
    {
    }
};

int main(int argc, char * argv[])
{
    // Parse the command line options
    cxxopts::Options options("DNS With Benefits", "DNS Resolver Server With Filtering Capabilities.");
    options.add_options()
    ("a,addr", "IP Address to listen on", cxxopts::value<std::string>()->default_value("127.0.0.1"))
    ("f,conf", "Routing Config File name", cxxopts::value<std::string>()->default_value(""))
    ("p,port", "Routing Config File name", cxxopts::value<uint16_t>()->default_value("53"))
    ("v,verbose", "Verbose Logging")
    ;
    auto result = options.parse(argc, argv);
    
    // Setup the networking configurations
    in_addr listen_host;
    inet_aton(result["addr"].as<std::string>().c_str(), &listen_host);
    sockaddr_in addr = {sizeof(sockaddr_in), AF_INET, htons(result["port"].as<uint16_t>()), listen_host, 0};
    
    // Construct the routing system
    DBRoutingSystem routing_system(result["conf"].as<std::string>());
    
    // Construct the DNS hypervisor
    DBDNSHypervisor dns_hypervisor((sockaddr *)&addr, &routing_system);
    
    // Start the threads
    dns_hypervisor.start_threads();
    
    for (;;)
        sleep(1);
    
    return 0;
}
