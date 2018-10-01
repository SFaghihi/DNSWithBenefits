//
//  DBDNSResolver.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBDNSResolver_hpp
#define DBDNSResolver_hpp

#include <iostream>
#include <map>
#include <list>

#include "DBDoTResolver.hpp"
#include "DBThreadingSystem.hpp"

class DBDNSResolverSystem
{
    template <typename K, typename V>
    using dict = std::map<K, V>;
private:
    // Threading Stuff
    prefiltered_buffer_t *resolving_queue;
    resolved_buffer_t *postfiltering_queue;
    postfiltered_buffer_t *send_response_queue;
    DBThreadPool<DBDNSResolverSystem> thread_pool;
    
    const size_t handlers_per_thread = 10;
    const size_t event_count = 10;
    
    // DNS handling
    dict<uint16_t, std::list<filtered_request_t *>> id_map;
    
public:
    DBDNSResolverSystem(size_t _thread_pool_count, prefiltered_buffer_t *resolving_queue, resolved_buffer_t *postfiltering_queue, postfiltered_buffer_t *send_response_queue)
    : resolving_queue(resolving_queue), postfiltering_queue(postfiltering_queue),
      send_response_queue(send_response_queue),
      thread_pool(*this, _thread_pool_count, &DBDNSResolverSystem::resolve_loop)
    {
        // Setup OpenSSL library
        DBDoTResolver::init_openssl();
    }
    
    void resolve_loop(DBThread<DBDNSResolverSystem> &thread)
    {
        // Cloudflare Stuff
        sockaddr_in resolver_addr =
        {
            sizeof(sockaddr_in),
            AF_INET,
            htons(853),
            inet_addr("1.1.1.1")
        };
        std::string resolver_hostname = "cloudflare-dns.com";
        
        // Event Based multiplexing
        int kq;
        struct kevent new_events[event_count];
        struct kevent set_env;
        timespec imm_timeout = {0};
        
        // Get new kernel queue
        kq = kqueue();
        if (kq == -1)
            throw Exception("kqueue error!");
        
        std::vector<DBDoTResolver> handlers;
        dict<int, size_t> fd_to_handler;
        for (size_t i = 0; i < handlers_per_thread; i++)
        {
            handlers.emplace_back(DBDoTResolver{kq, (const sockaddr *)&resolver_addr, resolver_hostname});
            fd_to_handler[handlers.back().get_sock_fd()] = i;
        }
        size_t round_robin_idx = 0;
        
        EV_SET(&set_env, resolving_queue->dequeue_fd(), EVFILT_READ, EV_ADD , 0, 0, static_cast<void *>(this));
        int res = kevent(kq, &set_env, 1, nullptr, 0, &imm_timeout);
        
        while (true)
        {
            if (thread.try_test_cancellation())
                break;
            
            ssize_t event_num = kevent(kq, nullptr, 0, new_events, (int)event_count, nullptr);
            if (event_num <= 0)
                throw Exception("An error with kevent!!!");
            
            for (size_t i = 0; i < event_num; i++)
            {
                if (thread.try_test_cancellation())
                    goto LOOP_CLEANUP;
                
                int fd = static_cast<int>(new_events[i].ident);
                if (fd == resolving_queue->dequeue_fd())
                {
                    std::optional<filtered_request_t *> filtered_req_opt = resolving_queue->try_dequeue();
                    if (!filtered_req_opt.has_value())
                        continue;
                    filtered_request_t *filtered_req = *filtered_req_opt;
                    
                    if (id_map.count(filtered_req->request->identification()) != 0)
                        id_map[filtered_req->request->identification()].push_back(filtered_req);
                    else
                    {
                        id_map[filtered_req->request->identification()].push_back(filtered_req);
                        handlers[round_robin_idx].resolve_nb(filtered_req->request.get());
                        
                        bool should_retry = false;
                        for (auto msg : handlers[round_robin_idx].proc_write_nb(should_retry))
                            (id_map[msg->identification()].front())->request.reset();
                        
                        if (should_retry)
                            handlers[round_robin_idx].proc_write_nb(should_retry);
                        
                        round_robin_idx = (round_robin_idx + 1) % handlers_per_thread;
                    }
                    continue;
                }
                
                if (fd_to_handler.count(fd) == 0)
                    continue;
                
                bool should_retry = false;
                auto& handler = handlers[fd_to_handler[fd]];
                
                if (new_events[i].flags & (EV_EOF | EV_ERROR))
                {
                    handler.reset_once();
                    handler.proc_write_nb(should_retry);
                    continue;
                }
                
                if (new_events[i].filter == EVFILT_READ)
                {
                    for (auto &msg : handler.proc_read_nb(should_retry))
                    {
                        uint16_t id = msg->identification();
                        filtered_request_t *filtered_req = id_map[id].front();
                        postfiltering_queue->enqueue(new resolved_response_t(filtered_req->incoming_addr, msg));
                        delete filtered_req;
                        id_map[id].pop_front();
                        if (id_map[id].size() > 0)
                        {
                            filtered_req = id_map[id].front();
                            handlers[round_robin_idx].resolve_nb(filtered_req->request.get());
                            round_robin_idx = (round_robin_idx + 1) % handlers_per_thread;
                        }
                        else
                        {
                            id_map.erase(id);
                        }
                    }
                    if (should_retry)
                        handler.proc_write_nb(should_retry);
                }
                else if (new_events[i].filter == EVFILT_WRITE)
                {
                    for (auto msg : handler.proc_write_nb(should_retry))
                        (id_map[msg->identification()].front())->request.reset();
                    
                    if (should_retry)
                        handler.proc_write_nb(should_retry);
                }
            }
                        
            if (thread.try_test_cancellation())
                break;
        }
        
    LOOP_CLEANUP:
        close(kq);
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

#endif /* DBDNSResolver_hpp */
