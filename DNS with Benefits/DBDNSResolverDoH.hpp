//
//  DBDNSResolver.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBDNSResolverDoH_hpp
#define DBDNSResolverDoH_hpp

#include <iostream>

#include "DBDoHResolver.hpp"
#include "DBThreadingSystem.hpp"

class DBDNSResolverSystem {
    
private:
    // Threading Stuff
    prefiltered_buffer_t *resolving_queue;
    resolved_buffer_t *postfiltering_queue;
    postfiltered_buffer_t *send_response_queue;
    DBThreadPool<DBDNSResolverSystem> thread_pool;
    
public:
    DBDNSResolverSystem(size_t _thread_pool_count, prefiltered_buffer_t *resolving_queue, resolved_buffer_t *postfiltering_queue, postfiltered_buffer_t *send_response_queue)
    : resolving_queue(resolving_queue), postfiltering_queue(postfiltering_queue),
    send_response_queue(send_response_queue),
    thread_pool(*this, _thread_pool_count, &DBDNSResolverSystem::resolve_loop)
    {
        // Setup curl library
        if (curl_global_init(CURL_GLOBAL_DEFAULT)) {
            perror("Curl Init");
            exit(1);
        }
    }
    
    void resolve_loop(DBThread<DBDNSResolverSystem> &thread)
    {
        DBDoHResolver handler("1.1.1.1");
        
        while (true)
        {
            if (thread.try_test_cancellation())
                break;
            
            std::optional<filtered_request_t *> filtered_req_opt = resolving_queue->dequeue();
            if (!filtered_req_opt.has_value())
                break;
            filtered_request_t * filtered_req = *filtered_req_opt;
            
            //std::cout << "QUERY:\n";
            //filtered_req->request->hex_dump(std::cout);
            std::unique_ptr<DBDNSMessage> response = handler.resolve(*filtered_req->request);
            //std::cout << "RESPONSE:\n";
            //response->hex_dump(std::cout);
            
            if (thread.try_test_cancellation())
                break;
            
            postfiltering_queue->enqueue(new resolved_response_t(filtered_req->incoming_addr, response));
            delete filtered_req;
        }
    }
    
    void stop_threads()
    {
        thread_pool.stop_threads();
    }
    
    void start_threads()
    {
        thread_pool.start_threads();
    }
    
};

#endif /* DBDNSResolverDoH_hpp */
