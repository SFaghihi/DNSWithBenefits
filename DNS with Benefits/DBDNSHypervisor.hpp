//
//  DBDNSHypervisor.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 6/24/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBDNSHypervisor_hpp
#define DBDNSHypervisor_hpp

#include <iostream>
#include <vector>
#include <signal.h>

#include "DBCommon.hpp"
#include "DBDNSServer.hpp"
#include "DBFilteringSystem.hpp"
#include "DBFilteringController.hpp"
#include "DBDNSResolverDoH.hpp"
#include "DBCircularBuffer.hpp"

class DBDNSHypervisor {
    static DBDNSHypervisor *_main_hypervisor;
    
public:
    
    struct thread_pool_count_t {
        size_t receiving;
        size_t prefiltering;
        size_t resolving;
        size_t postfiltering;
        size_t sending;
    };
    
    static constexpr thread_pool_count_t default_pool_count = {
        1,
        5,
        5,
        5,
        5
    };
    
    static DBDNSHypervisor *get_main_hypervisor() { return _main_hypervisor; }
    
    static void sig_reset_handler(int sig)
    {
        if (_main_hypervisor)
        {
            _main_hypervisor->prefilter_system.signal_reinit();
            _main_hypervisor->postfilter_system.signal_reinit();
        }
    }
    
private:
    
    // Threading
    thread_pool_count_t thread_pool_count;
    
    // Data Pipeline model
    translated_buffer_t prefiltering_queue;
    prefiltered_buffer_t resolving_queue;
    resolved_buffer_t postfiltering_queue;
    postfiltered_buffer_t send_response_queue;
        
    // Filtering System
    DBFilteringController *filtering_controller;
    DBPreFilteringSystem prefilter_system;
    DBPostFilteringSystem postfilter_system;
    
    // Resolving System
    DBDNSResolverSystem resolving_system;
    
    // Networking system
    DBDNSServer server_system;
    
public:
    DBDNSHypervisor(sockaddr *listen_addr, DBFilteringController *filtering_controller, thread_pool_count_t thread_pool_count = default_pool_count)
    :
    // Thread counts
    thread_pool_count(thread_pool_count),
    
    // Data Pipeline buffers
    prefiltering_queue(), resolving_queue(true),
    postfiltering_queue(), send_response_queue(),
    
    // Filtering system
    filtering_controller(filtering_controller),
    prefilter_system(filtering_controller, thread_pool_count.prefiltering, &prefiltering_queue, &resolving_queue, &postfiltering_queue),
    postfilter_system(filtering_controller, thread_pool_count.postfiltering, &postfiltering_queue, &send_response_queue),
    
    // Resolving System
    resolving_system(thread_pool_count.resolving, &resolving_queue, &postfiltering_queue, &send_response_queue),
    
    // Networking system
    server_system(listen_addr, thread_pool_count.receiving, thread_pool_count.sending, &prefiltering_queue, &send_response_queue)
    {
        // We become the main!!!
        if (_main_hypervisor != nullptr)
            throw Exception("There can only be one hypervisor running in a program!!!");
        _main_hypervisor = this;
        
        // Setup signal handling (We don't want the pesky SIGPIPE)
        signal(SIGPIPE, SIG_IGN);
        
        // We want to gracefully restart the filtering with a USR1 signal
        signal(SIGUSR1, &DBDNSHypervisor::sig_reset_handler);
    }
    
    ~DBDNSHypervisor()
    {
        // Stop the threads
        server_system.stop_threads();
        prefilter_system.stop_threads();
        resolving_system.stop_threads();
        postfilter_system.stop_threads();
        
        // Empty the queues
        while (!prefiltering_queue.is_empty())
            delete prefiltering_queue.dequeue().value_or(nullptr);
        
        while (!resolving_queue.is_empty())
            delete resolving_queue.dequeue().value_or(nullptr);
        
        while (!postfiltering_queue.is_empty())
            delete postfiltering_queue.dequeue().value_or(nullptr);
        
        while (!send_response_queue.is_empty())
            delete send_response_queue.dequeue().value_or(nullptr);
        
        // Stop being supreme
        _main_hypervisor = nullptr;
    }
    
    void start_threads()
    {
        server_system.start_threads();
        prefilter_system.start_threads();
        resolving_system.start_threads();
        postfilter_system.start_threads();
    }
    
};

#endif /* DBDNSHypervisor_hpp */
