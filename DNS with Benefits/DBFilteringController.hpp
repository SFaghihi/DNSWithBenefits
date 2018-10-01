//
//  DBFilteringController.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 6/24/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBFilteringController_hpp
#define DBFilteringController_hpp

#include <stdio.h>

#include "DBCommon.hpp"
#include "DBMatchSystem.hpp"

class DBPreFilteringSystem;
class DBPostFilteringSystem;

class DBFilteringController
{
protected:
    // Should writeout debug
    bool debug_on = false;
    
    friend class DBPreFilteringSystem;
    friend class DBPostFilteringSystem;
    
    // Mathing Systems for the filtering locations
    DBDNSMatchSystemPre *prefilter_match_system = nullptr;
    DBDNSMatchSystemPost *postfilter_match_system = nullptr;
    
    inline static std::string type_as_str(const std::set<uint16_t> &types)
    {
        std::string str = "{";
        bool is_first = true;
        for (auto type : types)
        {
            if (is_first)
                is_first = false;
            else
                str += ", ";
            str += DNSType_to_string(type);
        }
        str += "}";
        
        return str;
    }
    
    /*
     * Register function on match on DNS Query Request (Prefilter)
     * `hostname_pattern` is either complete match or left side wildcard using `*`
     * Example:
     *        1) www.apple.com
     *        2) *.google.com
     *        3) *nflx.net
     * `user_data` needs to be allocated using malloc
     * `callback_fnc` as part of the pipeline can modify the rquest, and by returning the false can block the request.
     * `callback_fnc` should never attempt to free the message!!!!
     * NB: This call is NOT thread safe!!! This should ONLY be called during initialization or reinitialization.
     */
    void register_match_query_unsafe(DBDNSTriePre &trie, const std::string &hostname_pattern, const std::set<uint16_t> &query_type, hostname_pre_match_callback_t callback_fnc, std::shared_ptr<void> user_data)
    {
        if (debug_on)
            std::cout << "Registering prematch => Type: " << type_as_str(query_type) << ", Hostname: '" << hostname_pattern << "'\n";
        pre_callback_fnc_t value(callback_fnc, query_type, user_data);
        trie[hostname_pattern].push_back(value);
    }
    void register_match_query_unsafe(DBDNSTriePost &trie, const std::string &hostname_pattern, const std::set<uint16_t> &query_type, hostname_post_match_callback_t callback_fnc, std::shared_ptr<void> user_data)
    {
        if (debug_on)
            std::cout << "Registering postmatch => Type: " << type_as_str(query_type) << ", Hostname: '" << hostname_pattern << "'\n";
        post_callback_fnc_t value(callback_fnc, query_type, user_data);
        trie[hostname_pattern].push_back(value);
    }
    
    /*
     * Register function on match on DNS Query Request (Prefilter)
     * `hostname_pattern` is either complete match or left side wildcard using `*`
     * Example:
     *        1) www.apple.com
     *        2) *.google.com
     *        3) *nflx.net
     * `user_data` needs to be allocated using malloc
     * `callback_fnc` as part of the pipeline can modify the rquest, and by returning the false can block the request.
     * `callback_fnc` should never attempt to free the message!!!!
     * NB: This call is thread safe. This is done using a read/write lock. Do NOT use this inside initialization.
     */
    void register_match_query_safe(DBDNSMatchSystemPre *match_system, const std::string &hostname_pattern, const std::set<uint16_t> &query_type, hostname_pre_match_callback_t callback_fnc, std::shared_ptr<void> user_data)
    {
        if (debug_on)
            std::cout << "Registering prematch => Type: " << type_as_str(query_type) << ", Hostname: '" << hostname_pattern << "'\n";
        pre_callback_fnc_t value(callback_fnc, query_type, user_data);
        match_system->insert(hostname_pattern, value);
    }
    void register_match_query_safe(DBDNSMatchSystemPost *match_system, const std::string &hostname_pattern, const std::set<uint16_t> &query_type, hostname_post_match_callback_t callback_fnc, std::shared_ptr<void> user_data)
    {
        if (debug_on)
            std::cout << "Registering postmatch => Type: " << type_as_str(query_type) << ", Hostname: '" << hostname_pattern << "'\n";
        post_callback_fnc_t value(callback_fnc, query_type, user_data);
        match_system->insert(hostname_pattern, value);
    }
    
public:
    DBFilteringController(bool debugon) : debug_on(debugon) {}
    
    virtual void prefilter_initializer(DBDNSTriePre &trie) = 0;
    virtual void postfilter_initializer(DBDNSTriePost &trie) = 0;
    
    virtual void prefilter_deconstructed() {}
    virtual void postfilter_deconstructed() {}
    
};

#endif /* DBFilteringController_hpp */
