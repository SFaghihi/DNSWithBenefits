//
//  DBRoutingSystem.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBRoutingSystem_hpp
#define DBRoutingSystem_hpp

// Networking stuff
#include <net/route.h>
#include <netinet/in.h>

// C++ Stuff
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

// Internal Stuff
#include "DBRouteUtility.h"
#include "DBUtility.hpp"
#include "DBFilteringController.hpp"
#include "DBDoHResolver.hpp"


class DBRoutingSystem : public DBFilteringController
{    
    bool initialized = false;
    
    std::string conf_path;
    static std::atomic<int> route_seq;
    int if_sock_inf = -1;
    static int route_sock;
    static int poll_timeout;
    
    struct route_msg_t {
        rt_msghdr msg_header;
        char msg_data[1024];
    };
    alignas(4096) route_msg_t route_get_msg = {0};
    std::mutex route_mtx;
    
    struct if_route_inf_t {
        bool accept = false;
        unsigned short gw_if = 0;
        in_addr ip4 = {0};
        in6_addr ip6 = {0};
    };
    
    std::unordered_map<unsigned int, std::shared_ptr<if_route_inf_t> > ifs_gw;
    
    std::unordered_map<std::string, std::string> alias_table;
    std::mutex alias_mtx;
    
    // Resolver Bits
    static constexpr size_t resolver_buffer_size = 5;
    using resolver_buffer_t = DBCircularBuffer<std::unique_ptr<DBDoHResolver>, resolver_buffer_size>;
    static resolver_buffer_t resolvers;
    static in_addr alt_resolve_addr;
    
    // Resolver Thread Synchronization Bits
    static std::shared_mutex resolver_route_shared_mutex;
    static std::mutex resolver_route_mutex;
    static std::condition_variable resolver_route_cv;
    static size_t resolver_route_owning_interface_ref_count;
    static unsigned short resolver_route_owning_interface;
    static bool resolver_route_is_reset;
    
    
    static inline int get_seq_id();
    static inline size_t round_up(size_t a);
    static inline bool is_ip_empty(const in_addr &addr);
    static inline bool is_ip_empty(const in6_addr &addr);
    static inline uint16_t get_query_type(const std::string &query_str);
    
    inline void get_if_inf(unsigned int if_index, std::shared_ptr<if_route_inf_t> routing_inf, sa_family_t inet_family);
    inline std::shared_ptr<if_route_inf_t> get_info_from_if(const std::string &interface, sa_family_t inet_family);
    
    static inline void set_route_header(rt_msghdr *msg_header, u_short rtm_msglen, u_char rtm_type, u_short gw_if);
    static inline bool write_to_route_sock(void *route_msg);
    static inline bool route_ip_gw(const in_addr& dst_ip, const in_addr& gw_ip, unsigned short gw_if);
    static inline bool route_ip_gw(const in6_addr& dst_ip, const in6_addr& gw_ip, unsigned short gw_if);
    
    static bool _route_dns_msg_callback(const DBDNSMessage &dns_msg, const DBDNSResourceRecord &record, const std::shared_ptr<void> &user_data);
    
    void init_alias_section(const std::string &config_str);
    
public:
    DBRoutingSystem(const std::string &conf_file, int _poll_timeout = 0);
    
    static DBFilterResult route_dns_msg_callback(DBDNSMessage &dns_msg, DBDNSResourceRecord &record, std::shared_ptr<void> user_data);
    static DBFilterResult resolve_dns_msg_callback(DBDNSMessage &dns_msg, DBDNSQuestionRecord &record, std::shared_ptr<void> user_data);
    
    virtual void prefilter_initializer(DBDNSTriePre &trie);
    virtual void postfilter_initializer(DBDNSTriePost &trie);
};

#endif /* DBRoutingSystem_hpp */
