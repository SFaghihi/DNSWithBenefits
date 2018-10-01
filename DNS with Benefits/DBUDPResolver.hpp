//
//  DBUDPResolver.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/22/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBUDPResolver_hpp
#define DBUDPResolver_hpp

#include <sys/time.h>
#include <openssl/ssl.h>

#include <iostream>

#include "Exception.hpp"
#include "DBCommon.hpp"
#include "DBDNSMessage.hpp"

class DBUDPResolver {
private:
    
    // resolver
    std::unique_ptr<DBDNSMessage> response_ptr;
    
    // CURL Manager
    array_unique_ptr<uint8_t> data;
    std::atomic<size_t> data_length = -1;
    std::vector<uint8_t> data_buffer;
    size_t data_idx = 0;
    std::atomic<bool> should_continue = true;
    std::atomic<bool> has_sent = false;
    
    long http_status_code = 0;
    
    bool update_code(long http_code);
    void reinit();
    
    void create_error_response(uint16_t RCODE);
    void create_response();
    
    static inline size_t is_header(const std::string &header, const std::string &buffer);
    
    static size_t header_handler(char *buffer_c, size_t size, size_t nitems, void *userdata);
    static size_t data_handler(char *data_c, size_t size, size_t nmemb, void *userdata);
    
public:
    DBUDPResolver(const std::string &resolver_addr);
    ~DBUDPResolver();
    
    const char *error() const;
    std::unique_ptr<DBDNSMessage> resolve(DBDNSMessage &request);
};


#endif /* DBUDPResolver_hpp */
