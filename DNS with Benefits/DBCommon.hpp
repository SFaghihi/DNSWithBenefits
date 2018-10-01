//
//  common.h
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/30/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef common_h
#define common_h

// Networking stuff
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <memory>
#include <set>

#include "DBUtility.hpp"
#include "DBDNSMessage.hpp"
#include "DBMatchSystem.hpp"
#include "DBCircularBuffer.hpp"

// Constants
#pragma Constants
const bool debug_print_on = false;

// Threading pool queue max count
const size_t queue_max_count = 50;

// Matching System Trie Radix
const int Trie_Radix = 4;

// Filter Location enums
enum DBFilterLocation
{
    DBFilterLocationPre = 0,
    DBFilterLocationPost = 1
};

// Filter Result enums
typedef enum DBFilterResult
{
    DBFilterAccept = 0,      // Accept the message and continue onto other filters.
    DBFilterReject,          // Reject the message and drop all the records.
    DBFilterSkipResolve,     // The message was manually resolved, skip resolving.
    DBFilterDropQuestion,    // Drop the question in the message.
    DBFilterDropRecord,      // Drop the record in the message.
    DBFilterSkipFilter,      // Skip filtering the record and/or question.
    DBFilterMessageModified, // Message modified, refilter the message.
    DBFilterRecordModified,  // Record modified, refilter the record.
    DBFilterQuestionModified // Question modified, refilter the question.
}
DBFilterResult;

// Data Structures
#pragma DataStructures

// Filtering Callback function type
// The DNS Response message can be modified.
// Return true to allow the answer through, else the answer is filtered.
// NB: Other functions might block the response afterwards.
typedef DBFilterResult (*hostname_pre_match_callback_t)(DBDNSMessage &dns_msg, DBDNSQuestionRecord &record, std::shared_ptr<void> user_data);

typedef DBFilterResult (*hostname_post_match_callback_t)(DBDNSMessage &dns_msg, DBDNSResourceRecord &record, std::shared_ptr<void> user_data);

// Prefilter Callback Structure with internal memory reference management
struct pre_callback_fnc_t {
public:
    hostname_pre_match_callback_t function;
    std::set<uint16_t> query_type;
    std::shared_ptr<void> user_data;
    
    pre_callback_fnc_t(hostname_pre_match_callback_t fnc, const std::set<uint16_t> &type, std::shared_ptr<void> user_data)
    : function(fnc), query_type(type), user_data(user_data)
    {}
    
    pre_callback_fnc_t(const pre_callback_fnc_t &source) = default;
    pre_callback_fnc_t(pre_callback_fnc_t &&source) = default;
    
    ~pre_callback_fnc_t()  = default;
    
    pre_callback_fnc_t &operator=(const pre_callback_fnc_t &source) =  default;
    pre_callback_fnc_t &operator=(pre_callback_fnc_t &&source) =  default;
};

// Postfilter Callback Structure with internal memory reference management
struct post_callback_fnc_t {
public:
    hostname_post_match_callback_t function;
    std::set<uint16_t> query_type;
    std::shared_ptr<void> user_data;
    
    post_callback_fnc_t(hostname_post_match_callback_t fnc, const std::set<uint16_t> &type, std::shared_ptr<void> user_data)
    : function(fnc), query_type(type), user_data(user_data)
    {}
    
    post_callback_fnc_t(const post_callback_fnc_t &source) = default;
    post_callback_fnc_t(post_callback_fnc_t &&source) = default;
    
    ~post_callback_fnc_t() = default;
    
    post_callback_fnc_t &operator=(const post_callback_fnc_t &source) =  default;
    post_callback_fnc_t &operator=(post_callback_fnc_t &&source) =  default;
};

// Received Structure directly from the network
struct received_request_t {
    sockaddr *incoming_addr;
    void *data;
    size_t data_length;
};

// Translated DNS Request to be prefiltered
struct translated_request_t {
    unique_sockaddr incoming_addr;
    std::unique_ptr<DBDNSMessage> request;
    
    translated_request_t(unique_sockaddr &_incoming_addr, std::unique_ptr<DBDNSMessage> &_request)
    : incoming_addr(std::move(_incoming_addr)), request(std::move(_request))
    {}
};

// Filtered DNS Request To be resolved
struct filtered_request_t {
    unique_sockaddr incoming_addr;
    std::unique_ptr<DBDNSMessage> request;
    
    filtered_request_t(translated_request_t *translated_req)
    : incoming_addr(std::move(translated_req->incoming_addr)), request(std::move(translated_req->request))
    { delete translated_req; }
};

// Resolved DNS response to be postfiltered
struct resolved_response_t {
    unique_sockaddr incoming_addr;
    std::unique_ptr<DBDNSMessage> response;
    
    resolved_response_t(unique_sockaddr &_incoming_addr, std::unique_ptr<DBDNSMessage> &_response)
    : incoming_addr(std::move(_incoming_addr)), response(std::move(_response))
    {}
};

// Filtered DNS response to be sent
struct filtered_response_t {
    unique_sockaddr incoming_addr;
    std::unique_ptr<DBDNSMessage> response;
    
    filtered_response_t(unique_sockaddr &_incoming_addr, std::unique_ptr<DBDNSMessage> &_response)
    : incoming_addr(std::move(_incoming_addr)), response(std::move(_response))
    {}
    
    filtered_response_t(resolved_response_t *resolved_res)
    : incoming_addr(std::move(resolved_res->incoming_addr)), response(std::move(resolved_res->response))
    { delete resolved_res; }
};

// Very useful typedefs for Data Pipeline system
using received_buffer_t     = DBCircularBuffer<received_request_t *, queue_max_count>;
using translated_buffer_t   = DBCircularBuffer<translated_request_t *, queue_max_count>;
using prefiltered_buffer_t  = DBCircularBuffer<filtered_request_t *, queue_max_count>;
using resolved_buffer_t     = DBCircularBuffer<resolved_response_t *, queue_max_count>;
using postfiltered_buffer_t = DBCircularBuffer<filtered_response_t *, queue_max_count>;

// Very useful typedefs for filtering system
using DBDNSTriePre = DBRadixTrie<Trie_Radix, std::vector<pre_callback_fnc_t>>;
using DBDNSTriePost = DBRadixTrie<Trie_Radix, std::vector<post_callback_fnc_t>>;
using DBDNSMatchSystemPre = DBMatchSystem<Trie_Radix, pre_callback_fnc_t>;
using DBDNSMatchSystemPost = DBMatchSystem<Trie_Radix, post_callback_fnc_t>;

#endif /* common_h */
