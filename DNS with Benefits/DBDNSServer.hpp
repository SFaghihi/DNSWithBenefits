//
//  DBDNSServer.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBDNSServer_hpp
#define DBDNSServer_hpp

#include <iostream>

#include "DBCircularBuffer.hpp"
#include "DBCommon.hpp"
#include "DBThreadingSystem.hpp"

class DBDNSServer {
private:
    // Networking Stuff
    const size_t udp_buffer_size = 4096;
    const sockaddr *listen_addr;
    int listen_sd;
    
    // Threading Stuff
    translated_buffer_t *prefiltering_queue;
    DBThreadPool<DBDNSServer> receiving_pool;
    postfiltered_buffer_t *sending_queue;
    DBThreadPool<DBDNSServer> sending_pool;
    
public:
    DBDNSServer(sockaddr *listen_addr, size_t receiving_thread_count, size_t sending_thread_count, translated_buffer_t *prefiltering_queue, postfiltered_buffer_t *sending_queue)
    : listen_addr(listen_addr), prefiltering_queue(prefiltering_queue), sending_queue(sending_queue),
      sending_pool(*this, sending_thread_count, &DBDNSServer::send_loop), receiving_pool(*this, receiving_thread_count, &DBDNSServer::main_loop)
    {
        listen_sd = socket(listen_addr->sa_family, SOCK_DGRAM, 0);
        if (listen_sd < 0)
            throw Exception("Couldn't open listenning socket!");
        
        int err = bind(listen_sd, listen_addr, listen_addr->sa_len);
        if (err)
            throw Exception("Couldn't bind listenning socket!");
    }
    
    void main_loop(DBThread<DBDNSServer> &thread)
    {
        std::shared_ptr<uint8_t> buffer(new uint8_t[udp_buffer_size], array_deleter<uint8_t>());
        
        while (true)
        {
            if (thread.try_test_cancellation())
                break;
            
            socklen_t incoming_addr_length = listen_addr->sa_len;
            unique_sockaddr incoming_addr((sockaddr *)malloc(listen_addr->sa_len));
            sockaddr *in_ptr = incoming_addr.get();
            
            ssize_t read_length = recvfrom(listen_sd, buffer.get(), udp_buffer_size, 0, in_ptr, &incoming_addr_length);
            
            //std::cout << "Read:  0x" << std::hex << in_ptr << std::dec << " sock_len->" << (uint16_t)in_ptr->sa_len << " sock_fa->" << (uint16_t)in_ptr->sa_family << "\n";
            
            std::unique_ptr<DBDNSMessage> dns_msg = std::unique_ptr<DBDNSMessage>(new DBDNSMessage(buffer, read_length, DBDNSMessage::DNSQueryType));
            if (!dns_msg->is_good())
                continue;
            
            translated_request_t *translated_request = new translated_request_t(incoming_addr, dns_msg);
            
            if (thread.try_test_cancellation())
                break;
            
            prefiltering_queue->enqueue(translated_request);
        }
    }
    
    void send_loop(DBThread<DBDNSServer> &thread)
    {
        while (true) {
        SEND_LOOP_START:
            if (thread.try_test_cancellation())
                return;
            
            std::optional<filtered_response_t *> filtered_response_opt = sending_queue->dequeue();
            if (!filtered_response_opt.has_value())
                break;
            filtered_response_t *filtered_response = *filtered_response_opt;
            
            const void *data = (const void *)filtered_response->response->bytes();
            size_t length = filtered_response->response->bytes_length();
            
            if (thread.try_test_cancellation())
                return;
            
            sockaddr *in_ptr = filtered_response->incoming_addr.get();
            //std::cout << "Write: 0x" << std::hex << in_ptr << std::dec << " sock_len->" << (uint16_t)in_ptr->sa_len << " sock_fa->" << (uint16_t)in_ptr->sa_family << "\n";
            
            ssize_t written = sendto(listen_sd, data, length, 0, in_ptr, filtered_response->incoming_addr->sa_len);
            if (written != length)
                perror("Couldn't send to the incoming socket!!! : ");
            
            delete filtered_response;
        }
    }
    
    void stop_threads()
    {
        receiving_pool.stop_threads();
        sending_pool.stop_threads();
    }
    
    void start_threads()
    {
        receiving_pool.start_threads();
        sending_pool.start_threads();
    }
};

#endif /* DBDNSServer_hpp */
