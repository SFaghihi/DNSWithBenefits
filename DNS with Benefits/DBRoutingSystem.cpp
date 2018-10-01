//
//  DBRoutingSystem.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/31/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBRoutingSystem.hpp"

#include <iostream>

// System Stuff
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>

// Parsing Stuff
#include <pcrecpp.h>
#include <string>
#include <fstream>
#include <sstream>

// Networking Stuff
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "DBScriptRunner.hpp"

/************************** Start of DBRoutingSystem *****************************/

// Static Variables

//int DBRoutingSystem::if_sock_inf = -1;
int DBRoutingSystem::route_sock = -1;
std::atomic<int> DBRoutingSystem::route_seq;

int DBRoutingSystem::poll_timeout;

DBRoutingSystem::resolver_buffer_t DBRoutingSystem::resolvers;
in_addr DBRoutingSystem::alt_resolve_addr = {0};

std::shared_mutex DBRoutingSystem::resolver_route_shared_mutex;
std::mutex DBRoutingSystem::resolver_route_mutex;
std::condition_variable DBRoutingSystem::resolver_route_cv;
size_t DBRoutingSystem::resolver_route_owning_interface_ref_count = 0;
unsigned short DBRoutingSystem::resolver_route_owning_interface = 0;
bool DBRoutingSystem::resolver_route_is_reset = false;

//std::unordered_map<unsigned int, std::shared_ptr<DBRoutingSystem::if_route_inf_t> > DBRoutingSystem::ifs_gw;
//DBRoutingSystem::route_msg_t DBRoutingSystem::route_get_msg;



// Private
inline int DBRoutingSystem::get_seq_id() { return route_seq++; }

inline bool DBRoutingSystem::is_ip_empty(const in6_addr &addr)
{
    return !(addr.__u6_addr.__u6_addr32[0] | addr.__u6_addr.__u6_addr32[1] | addr.__u6_addr.__u6_addr32[2] | addr.__u6_addr.__u6_addr32[3]);
}

inline bool DBRoutingSystem::is_ip_empty(const in_addr &addr) { return addr.s_addr == 0; }

inline size_t DBRoutingSystem::round_up(size_t a) { return a > 0 ? (1 + ((a - 1) | 3)) : 4; }

inline void DBRoutingSystem::get_if_inf(unsigned int if_index, std::shared_ptr<if_route_inf_t> routing_inf, sa_family_t inet_family)
{
    std::unique_lock<std::mutex> lck(route_mtx);
    //route_msg_t route_get_msg = {0};
    bzero(&route_get_msg, sizeof(route_get_msg));
    
    route_get_msg.msg_header.rtm_version = RTM_VERSION;
    route_get_msg.msg_header.rtm_type = RTM_GET;
    route_get_msg.msg_header.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_IFSCOPE;
    route_get_msg.msg_header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP;
    
    // Get process id
    pid_t pid = getpid();
    route_get_msg.msg_header.rtm_pid = 0;
    
    // Get a new unique seq_id
    int seq_id = get_seq_id();
    route_get_msg.msg_header.rtm_seq = seq_id;
    
    // Actual interface index
    route_get_msg.msg_header.rtm_index = if_index;
    
    // Create the get message
    char *msg_end = NULL;
    if (inet_family == AF_INET) {
        sockaddr_in *dst_so = (sockaddr_in *) (route_get_msg.msg_data);
        sockaddr_in *gw_so = (sockaddr_in *) (route_get_msg.msg_data + round_up(sizeof(sockaddr_in)));
        sockaddr *msk_so = (sockaddr *) ((char *)gw_so + round_up(sizeof(sockaddr_in)));
        sockaddr_dl *ifp_so = (sockaddr_dl *) ((char *)msk_so + round_up(sizeof(sockaddr)));
        msg_end = (char *)ifp_so + round_up(sizeof(sockaddr_dl));
        
        dst_so->sin_len = sizeof(sockaddr_in);
        dst_so->sin_family = AF_INET;
        
        gw_so->sin_len = sizeof(sockaddr_in);
        gw_so->sin_family = AF_INET;
        
        msk_so->sa_len = sizeof(sockaddr);
        msk_so->sa_family = AF_INET;
        
        ifp_so->sdl_alen = sizeof(sockaddr_dl);
        ifp_so->sdl_family = AF_LINK;
    } else if (inet_family == AF_INET6) {
        sockaddr_in6 *dst_so = (sockaddr_in6 *) (route_get_msg.msg_data);
        sockaddr_in6 *gw_so = (sockaddr_in6 *) (route_get_msg.msg_data + round_up(sizeof(sockaddr_in6)));
        sockaddr *msk_so = (sockaddr *) ((char *)gw_so + round_up(sizeof(sockaddr_in6)));
        sockaddr_dl *ifp_so = (sockaddr_dl *) ((char *)msk_so + round_up(sizeof(sockaddr)));
        msg_end = (char *)ifp_so + round_up(sizeof(sockaddr_dl));
        
        dst_so->sin6_len = sizeof(sockaddr_in6);
        dst_so->sin6_family = AF_INET6;
        
        gw_so->sin6_len = sizeof(sockaddr_in6);
        gw_so->sin6_family = AF_INET6;
        
        msk_so->sa_len = sizeof(sockaddr);
        msk_so->sa_family = AF_INET;
        
        ifp_so->sdl_alen = sizeof(sockaddr_dl);
        ifp_so->sdl_family = AF_LINK;
    } else {
        std::cout << "Unsupported Sock Addr Family: " << inet_family << "\n";
        return;
    }
    
    // Calculate message length
    route_get_msg.msg_header.rtm_msglen = msg_end - (char *)&route_get_msg;
    
    // Write to socket
    pollfd fds[1];
    fds[0] = {if_sock_inf, POLLOUT, 0};
    if (poll(fds, 1, poll_timeout) <= 0) {
        perror("Sock write poll");
        return;
    }
    ssize_t res_len = write(if_sock_inf, (void *)&route_get_msg, route_get_msg.msg_header.rtm_msglen);
    
    if (res_len != route_get_msg.msg_header.rtm_msglen) {
        perror("Sock write");
        return;
    }
    
    do {
        fds[0] = {if_sock_inf, POLLIN, 0};
        if (poll(fds, 1, poll_timeout) <= 0){
            perror("Sock read poll");
            return;
        }
        res_len = read(if_sock_inf, (void *)&route_get_msg, sizeof(route_get_msg));
    } while (res_len > 0 && (route_get_msg.msg_header.rtm_seq != seq_id || route_get_msg.msg_header.rtm_pid != pid));
    
    if (res_len <= 0) {
        perror("Sock read");
        return;
    }
    
    if (route_get_msg.msg_header.rtm_errno || !(route_get_msg.msg_header.rtm_flags & RTF_GATEWAY)) {
        std::cout << "Route errorno: " << route_get_msg.msg_header.rtm_errno << "\n";
        return;
    }
    
    if (inet_family != AF_INET6) {
        sockaddr_in *adr_ptr = (sockaddr_in *)route_get_msg.msg_data;
        if (route_get_msg.msg_header.rtm_addrs & RTA_DST)
            adr_ptr = (sockaddr_in *)((char *)route_get_msg.msg_data + adr_ptr->sin_len);
        
        memcpy(&routing_inf->ip4, &(adr_ptr->sin_addr), sizeof(in_addr));
    } else {
        sockaddr_in6 *adr_ptr = (sockaddr_in6 *)route_get_msg.msg_data;
        if (route_get_msg.msg_header.rtm_addrs & RTA_DST)
            adr_ptr = (sockaddr_in6 *)((char *)route_get_msg.msg_data + adr_ptr->sin6_len);
        
        memcpy(&routing_inf->ip6, &(adr_ptr->sin6_addr), sizeof(in6_addr));
    }
}

inline std::shared_ptr<DBRoutingSystem::if_route_inf_t> DBRoutingSystem::get_info_from_if(const std::string &interface, sa_family_t inet_family)
{
    if (!interface.length())
    {
        std::shared_ptr<if_route_inf_t> res = std::make_shared<if_route_inf_t>();
        res->accept = false;
        return res;
    }
    
    unsigned int if_index = if_nametoindex(interface.c_str());
    if (!if_index)
    {
        std::cout << "No Interface with name " << interface << " Found!\n";
        return std::shared_ptr<if_route_inf_t>();
    }
    
    // Return cache result
    if (ifs_gw.count(if_index)) {
        std::shared_ptr<if_route_inf_t> curr_inf = ifs_gw[if_index];
        if ((inet_family == AF_UNSPEC || inet_family == AF_INET) && is_ip_empty(curr_inf->ip4))
            get_if_inf(if_index, curr_inf, AF_INET);
        if ((inet_family == AF_UNSPEC || inet_family == AF_INET6) && is_ip_empty(curr_inf->ip6))
            get_if_inf(if_index, curr_inf, AF_INET6);
        return curr_inf;
    }
    
    std::shared_ptr<if_route_inf_t> routing_inf(new if_route_inf_t());
    routing_inf->gw_if = if_index;
    routing_inf->accept = true;
    
    if ((inet_family == AF_UNSPEC || inet_family == AF_INET))
        get_if_inf(if_index, routing_inf, AF_INET);
    
    if ((inet_family == AF_UNSPEC || inet_family == AF_INET6))
        get_if_inf(if_index, routing_inf, AF_INET6);
    
    ifs_gw[if_index] = routing_inf;
    
    return ifs_gw[if_index];
}

inline uint16_t DBRoutingSystem::get_query_type(const std::string &query_str)
{
    if (query_str == "A")
        return kDNSType_A;
    else if (query_str == "AAAA")
        return kDNSType_AAAA;
    else
        return kDNSQType_ANY;
}

inline void DBRoutingSystem::set_route_header(rt_msghdr *msg_header, u_short rtm_msglen, u_char rtm_type, u_short gw_if)
{
    bzero(msg_header, sizeof(rt_msghdr));
    
    msg_header->rtm_msglen = rtm_msglen;
    msg_header->rtm_version = RTM_VERSION;
    msg_header->rtm_type = rtm_type;
    msg_header->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_HOST;
    msg_header->rtm_addrs = RTA_DST | RTA_GATEWAY;
    
    // Actual interface index
    msg_header->rtm_index = 0;
    
    // Get a new unique seq_id
    msg_header->rtm_seq = get_seq_id();
}

inline bool DBRoutingSystem::write_to_route_sock(void *route_msg)
{
    rt_msghdr *msg_header = (rt_msghdr *)route_msg;
    //print_rtmsg(msg_header, msg_header->rtm_msglen);
    // Write to socket
    pollfd fds[1];
    fds[0] = {route_sock, POLLOUT, POLLNVAL};
    if (poll(fds, 1, poll_timeout) <= 0)
        return false;
    if (fds[0].revents & POLLNVAL) {
        route_sock = -1;
        return false;
    }
    if (fds[0].revents & (POLLHUP | POLLERR)) {
        close(route_sock);
        route_sock = -1;
        return false;
    }
    ssize_t res_len = write(route_sock, route_msg, msg_header->rtm_msglen);
    
    return res_len == msg_header->rtm_msglen;
}

inline bool DBRoutingSystem::route_ip_gw(const in_addr& dst_ip, const in_addr& gw_ip, unsigned short gw_if)
{
    long pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1)
    {
        perror("sysconf");
        return false;
    }
    
    struct route_msg_t {
        rt_msghdr msg_header;
        sockaddr_in dst_so;
        sockaddr_in gw_so;
    } *route_msg_ptr = NULL;
    
    if (posix_memalign((void **)&route_msg_ptr, pagesize, 4 * pagesize) != 0) {
        perror("posix_memalign");
        return false;
    }
    
    route_msg_t &route_msg = *route_msg_ptr;
    
    // Set the header
    set_route_header((rt_msghdr *)&route_msg, sizeof(route_msg), RTM_ADD, gw_if);
    
    // Create the get message
    route_msg.dst_so.sin_len = sizeof(sockaddr_in);
    route_msg.dst_so.sin_family = AF_INET;
    memcpy((void *)&route_msg.dst_so.sin_addr, (void *)&dst_ip, sizeof(in_addr));
    
    route_msg.gw_so.sin_len = sizeof(sockaddr_in);
    route_msg.gw_so.sin_family = AF_INET;
    memcpy((void *)&route_msg.gw_so.sin_addr, (void *)&gw_ip, sizeof(in_addr));
    
    // Write to socket
    if (!write_to_route_sock((void *)&route_msg))
    {
        if (errno == EEXIST)
        {
            // Set the header
            set_route_header((rt_msghdr *)&route_msg, sizeof(route_msg), RTM_CHANGE, gw_if);
            
            // Create the get message
            route_msg.dst_so.sin_len = sizeof(sockaddr_in);
            route_msg.dst_so.sin_family = AF_INET;
            memcpy((void *)&route_msg.dst_so.sin_addr, (void *)&dst_ip, sizeof(in_addr));
            
            route_msg.gw_so.sin_len = sizeof(sockaddr_in);
            route_msg.gw_so.sin_family = AF_INET;
            memcpy((void *)&route_msg.gw_so.sin_addr, (void *)&gw_ip, sizeof(in_addr));
            
            if (!write_to_route_sock((void *)&route_msg))
            {
                perror("Sock route change");
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    
    return true;
}

inline bool DBRoutingSystem::route_ip_gw(const in6_addr& dst_ip, const in6_addr& gw_ip, unsigned short gw_if)
{
    long pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1)
    {
        perror("sysconf");
        return false;
    }
    
    struct route_msg_t {
        rt_msghdr msg_header;
        sockaddr_in6 dst_so;
        sockaddr_in6 gw_so;
    } *route_msg_ptr = NULL;
    
    if (posix_memalign((void **)&route_msg_ptr, pagesize, 4 * pagesize) != 0) {
        perror("posix_memalign");
        return false;
    }
    
    route_msg_t &route_msg = *route_msg_ptr;
    
    // Set the header
    set_route_header((rt_msghdr *)&route_msg, sizeof(route_msg), RTM_ADD, gw_if);
    
    // Create the get message
    route_msg.dst_so.sin6_len = sizeof(sockaddr_in6);
    route_msg.dst_so.sin6_family = AF_INET6;
    memcpy((void *)&route_msg.dst_so.sin6_addr, (void *)&dst_ip, sizeof(in6_addr));
    
    route_msg.gw_so.sin6_len = sizeof(sockaddr_in6);
    route_msg.gw_so.sin6_family = AF_INET6;
    memcpy((void *)&route_msg.gw_so.sin6_addr, (void *)&gw_ip, sizeof(in6_addr));
    
    // Write to socket
    if (!write_to_route_sock((void *)&route_msg))
    {
        if (errno == EEXIST)
        {
            // Set the header
            set_route_header((rt_msghdr *)&route_msg, sizeof(route_msg), RTM_CHANGE, gw_if);
            
            // Create the get message
            route_msg.dst_so.sin6_len = sizeof(sockaddr_in6);
            route_msg.dst_so.sin6_family = AF_INET6;
            memcpy((void *)&route_msg.dst_so.sin6_addr, (void *)&dst_ip, sizeof(in6_addr));
            
            route_msg.gw_so.sin6_len = sizeof(sockaddr_in6);
            route_msg.gw_so.sin6_family = AF_INET6;
            memcpy((void *)&route_msg.gw_so.sin6_addr, (void *)&gw_ip, sizeof(in6_addr));
            
            if (!write_to_route_sock((void *)&route_msg))
            {
                perror("Sock route change");
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    
    return true;
}


bool DBRoutingSystem::_route_dns_msg_callback(const DBDNSMessage &dns_msg, const DBDNSResourceRecord &record, const std::shared_ptr<void> &user_data)
{
    const std::shared_ptr<if_route_inf_t> &gw_info = std::static_pointer_cast<if_route_inf_t>(user_data);
    char buf[IFNAMSIZ];
    std::cout << "YUP: " << record.query_type << ") " << record.domain_name() << "(" << inet_ntoa(*(in_addr *)record.data()) << ")  -> " << inet_ntoa(gw_info->ip4) << " : " << (if_indextoname(gw_info->gw_if, buf) ? buf : "?") << (gw_info->accept ? " Accept" : " Reject")<< "\n";
    if (!gw_info->accept)
        return false;
    
    if (record.query_type == kDNSType_A)
    {
        return route_ip_gw(*(in_addr *)record.data(), gw_info->ip4, gw_info->gw_if);
    }
    else if (record.query_type == kDNSType_AAAA)
    {
        return route_ip_gw(*(in6_addr *)record.data(), gw_info->ip6, gw_info->gw_if);
    }
    else if (record.query_type == kDNSType_CNAME)
    {
        std::string redirect_name((const char *)record.data());
        //std::cout << "*CNAME: " << redirect_name << " ->\n";
        for (const auto& rec : dns_msg.answers()) {
            //std::cout << rec.domain_name() << " : " << (rec.domain_name() == redirect_name) << "\n";
            if (rec.domain_name() == redirect_name)
                if (!_route_dns_msg_callback(dns_msg, rec, user_data))
                    return false;
        }
    }
    
    return true;
}


// Constructors
DBRoutingSystem::DBRoutingSystem(const std::string &conf_file, int _poll_timeout)
: conf_path(conf_file), DBFilteringController(debug_print_on)
{
    poll_timeout = _poll_timeout;
    setuid(geteuid());
    
    /*interfaces(1);
     
     //Routing Table:
     int mib[6];
     mib[0] = CTL_NET;
     mib[1] = PF_ROUTE;
     mib[2] = 0;       // protocol
     mib[3] = 0;       // wildcard address family
     mib[4] = NET_RT_DUMP;
     mib[5] = 0;       // no flags
     size_t needed = 0;
     if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
     perror("route-sysctl-estimate");
     
     uint8_t *data = (uint8_t *)malloc(needed), *next, *limit;
     size_t data_len = needed;
     if (sysctl(mib, 6, (void *)data, &data_len, NULL, 0) < 0)
     perror("sysctl");
     hex_dump_data(data_len, data, std::cout, 20);
     limit = data + data_len;
     rt_msghdr *rtm = NULL;
     for (next = data; next < limit; next += rtm->rtm_msglen)
     {
     rtm = (struct rt_msghdr *)next;
     print_rtmsg(rtm, rtm->rtm_msglen);
     }
     
     free(data);
     //exit(-1);
     */
    
    if (conf_path == "") {
        conf_path = "/etc/DwB.conf";
    }
    int testfd = open(conf_path.c_str(), O_RDONLY | O_CREAT, 0600);
    if (testfd > 0)
        close(testfd);
    else
        throw Exception("Configuration file open error!");
}

void DBRoutingSystem::init_alias_section(const std::string &config_str)
{
    if (!initialized)
    {
        // Clear out old Alias table
        alias_table.clear();
        
        // Parse the Alias sections of config file
        std::cout << "Parsing and initing conf file: " << conf_path << " in postfilter\n";
        
        std::string section;
        pcrecpp::StringPiece input(config_str);
        pcrecpp::RE re("[Aa]lias\\s*\\{\\s*([^\\{\\}]*)\\}");
        
        while (re.FindAndConsume(&input, &section))
        {
            std::istringstream conf(section);
            
            for (std::string line; std::getline(conf, line); )
            {
                ltrim(line);
                
                std::istringstream line_stream(line);
                std::string alias, eq_sign;
                line_stream >> alias;
                
                if (!alias.length() || alias[0] == '#')
                    continue;
                
                line_stream >> eq_sign;
                
                if (!std::set<std::string>({"=", ":=", ":"}).count(eq_sign))
                    throw Exception("Error: Syntax error in conf file in section Alias! line: \n" + line + "\nResolve Option -> alias: " + alias + "\n");
                
                std::string rest;
                std::getline(line_stream, rest);
                ltrim(rest);
                //std::cout << "Alias: " << alias << " eq: " << eq_sign << " rest: " << rest << "\n";
                if (rest[0] == '$')
                {
                    // Bash Script inside $( script )
                    size_t paran_count = 1, i = 2;
                    for (; i < rest.length(); i++)
                    {
                        if (rest[i] == '(')
                            ++paran_count;
                        else if (rest[i] == ')')
                        {
                            --paran_count;
                            if (paran_count == 0)
                                break;
                            else if (paran_count < 0)
                                break;
                        }
                    }
                    
                    if (paran_count != 0)
                    {
                        throw Exception("Error: Syntax error in conf file in section Alias, bash script! line: \n" + line + "\n");
                    }
                    else if (paran_count == 0)
                    {
                        std::string script_str = rest.substr(2, i - 2);
                        trim(script_str);
                        std::cout << "Alias (script): " << alias << ": <script> " << script_str << " </script> -> ";
                        DBScriptRunner script(script_str); script.execute("nobody", false);
                        std::cout << "ExitCode: " << (int)script.exit_code() << ", Output: " << script.output() << ", Error: " << script.error() << "\n";
                        
                        if (script)
                            alias_table[alias] = trim_copy(script.output());
                        else
                            alias_table[alias] = "";
                    }
                    
                }
                else
                {
                    rtrim(rest);
                    std::istringstream value_stream(rest);
                    std::string value;
                    value_stream >> value;
                    
                    if (!value_stream.eof())
                        throw Exception("Error: Syntax error in conf file in section Alias! line: \n" + line + "\nResolve Option -> alias: " + alias + " = " + value + "\n");
                    
                    alias_table[alias] = value;
                    
                    std::cout << "Alias (value): " << alias << " = " << value << "\n";
                }
                
            }
            
            // Seems to be needed!!!
            section.clear();
        }
        
        // Let there be no cached mDNSResponder!!!!! :)))))
        DBScriptRunner script("dscacheutil -flushcache; killall -HUP mDNSResponder"); script.execute("root", false);
    }
    initialized = !initialized;
}

// Public
void DBRoutingSystem::prefilter_initializer(DBDNSTriePre &trie)
{
    //std::cout << "We In Prefilter Init!!!\n";
    
    // Make sure no other resolver callback is running
    {
        std::unique_lock<std::mutex> lock(resolver_route_mutex);
        resolver_route_is_reset = true;
        resolver_route_cv.notify_all();
    }
    
    {
        //std::cout << "We In Prefilter Init 2!!!\n";
        std::unique_lock<std::shared_mutex> write_lock(resolver_route_shared_mutex);
        
        // Init the alternative resolver ip addr
        inet_pton(AF_INET, "1.0.0.1", &alt_resolve_addr);
        
        // Init the resolvers
        if (resolvers.is_empty())
            for (size_t i = 0; i < resolver_buffer_size; i++)
                resolvers.enqueue(std::unique_ptr<DBDoHResolver>(new DBDoHResolver("1.0.0.1")));
        
        // Open the routing info socket if needed
        {
            std::unique_lock<std::mutex> lck(route_mtx);
            
            if (if_sock_inf < 0)
                if_sock_inf = socket(PF_ROUTE, SOCK_RAW, AF_INET);
            
            if (if_sock_inf < 0)
                perror("Info Route socket open");
            
            if (route_sock < 0)
            {
                route_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
                if (if_sock_inf >= 0) {
                    int opt = 0;
                    setsockopt(route_sock, SOL_SOCKET, SO_USELOOPBACK, &opt, sizeof(opt));
                    shutdown(route_sock, SHUT_RD);
                }
                else
                    perror("Route socket open");
            }
        }
        
        // Read conf file into memory
        std::ifstream conf_file(conf_path);
        std::stringstream conf_buffer;
        conf_buffer << conf_file.rdbuf();
        std::string conf_str = conf_buffer.str();
        
        init_alias_section(conf_str);
        
        // Parse the resolve sections of config file
        std::cout << "Parsing the resolve sections!\n";

        pcrecpp::StringPiece input(conf_str);
        pcrecpp::RE re("[rR]esolve\\s+(\\w+)\\s*\\{\\s*([^\\{\\}]*)\\}");
        std::string interface, section;
        
        while (re.FindAndConsume(&input, &interface, &section))
        {
            if (alias_table.count(interface))
                interface = alias_table[interface];
            
            std::shared_ptr<if_route_inf_t> user_data = std::make_shared<if_route_inf_t>();
            if (inet_pton(AF_INET, interface.c_str(), &user_data->ip4) == 1)
                user_data->accept = true;
            else
                user_data = get_info_from_if(interface, AF_INET);
            
            if (!user_data) {
                std::cout << "No Interface with name " << interface << " Found!\n";
                continue;
            }
            
            std::istringstream conf(section);
            for (std::string line; std::getline(conf, line); )
            {
                trim(line);
                std::istringstream line_stream(line);
                std::string hostname, query_type;
                
                line_stream >> hostname;
                if (!hostname.length() || hostname[0] == '#')
                    continue;
                
                line_stream >> query_type;
                if (!line_stream.eof())
                    throw Exception("Error: Syntax error in conf file! line: \n" + line + "\nResolve Option -> hostname: " + hostname + ", query_type: " + query_type + ", routing_interface: " + interface);
                
                uint16_t type = get_query_type(query_type);
                sa_family_t inet_family;
                switch (type)
                {
                    case kDNSType_A:
                        inet_family = AF_INET;
                        break;
                    case kDNSType_AAAA:
                        inet_family = AF_INET6;
                        break;
                    default:
                        inet_family = AF_UNSPEC;
                        break;
                }
                
                register_match_query_unsafe(trie, hostname, std::set<uint16_t>({type}), &resolve_dns_msg_callback, user_data);
            }
            
            // Seems to be needed!!!
            section.clear(); interface.clear();
        }
        
        resolver_route_is_reset = false;
    }
    
    return;
}

void DBRoutingSystem::postfilter_initializer(DBDNSTriePost &trie)
{
    
    // Open the routing info socket if needed
    {
        std::unique_lock<std::mutex> lck(route_mtx);
        
        if (if_sock_inf < 0)
            if_sock_inf = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
        
        if (if_sock_inf < 0)
            perror("Info Route socket open");
        
        if (route_sock < 0)
        {
            route_sock = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
            if (if_sock_inf >= 0) {
                int opt = 0;
                setsockopt(route_sock, SOL_SOCKET, SO_USELOOPBACK, &opt, sizeof(opt));
                shutdown(route_sock, SHUT_RD);
            }
            else
                perror("Route socket open");
        }
    }
    
    {
        std::unique_lock<std::mutex> lock(alias_mtx);
        
        // Clear out routing info cache
        ifs_gw.clear();
        
        // Read conf file into memory
        std::ifstream conf_file(conf_path);
        std::stringstream conf_buffer;
        conf_buffer << conf_file.rdbuf();
        std::string conf_str = conf_buffer.str();
        
        init_alias_section(conf_str);
        
        // Parse the route sections of config file
        std::cout << "Parsing the route sections!\n";
        
        std::string section;
        pcrecpp::StringPiece input(conf_str);
        pcrecpp::RE re("[rR]oute\\s*\\{\\s*([^\\{\\}]*)\\}");
        
        while (re.FindAndConsume(&input, &section))
        {
            //std::cout << "Section: \n{\n" << "}\n";
            
            std::istringstream conf(section);
            
            for (std::string line; std::getline(conf, line); )
            {
                trim(line);
                
                std::istringstream line_stream(line);
                std::string hostname, query_type, routing_interface;
                line_stream >> hostname;
                
                if (!hostname.length() || hostname[0] == '#')
                    continue;
                
                line_stream >> query_type >> routing_interface;
                
                if (alias_table.count(routing_interface))
                    routing_interface = alias_table[routing_interface];
                
                if (!line_stream.eof())
                    throw Exception("Error: Syntax error in conf file! line: \n" + line + "\nRoute Option -> hostname: " + hostname + ", query_type: " + query_type + ", routing_interface: " + routing_interface);
                
                uint16_t type = get_query_type(query_type);
                std::shared_ptr<if_route_inf_t> user_data = std::make_shared<if_route_inf_t>();
                
                switch (type)
                {
                    case kDNSType_A:
                        if (inet_pton(AF_INET, routing_interface.c_str(), &user_data->ip4) != 1)
                            user_data = get_info_from_if(routing_interface, AF_INET);
                        else
                            user_data->accept = true;
                        break;
                        
                    case kDNSType_AAAA:
                        if (inet_pton(AF_INET6, routing_interface.c_str(), &user_data->ip4) != 1)
                            user_data = get_info_from_if(routing_interface, AF_INET6);
                        break;
                        
                    default:
                        user_data = get_info_from_if(routing_interface, AF_UNSPEC);
                        break;
                }
                
                if (!user_data)
                    continue;
                
                //char ipv6_str[INET6_ADDRSTRLEN + 1];
                //inet_ntop(AF_INET6, &user_data->ip6, ipv6_str, INET6_ADDRSTRLEN);
                //std::cout << "Result: gw4 " << inet_ntoa(user_data->ip4) << " gw6 " << ipv6_str << "\n";
                
                register_match_query_unsafe(trie, hostname, std::set<uint16_t>({type, kDNSType_CNAME}), &route_dns_msg_callback, user_data);
            }
        }
        
        //std::cout << "POSTFILTER TRie:\n" << trie << "\n";
    }

    /*
     // Test Routing setup
     in_addr dst_ip;
     inet_pton(AF_INET, "4.5.6.7", &dst_ip);
     if_route_inf_t *user_data = get_info_from_if("en0");
     route_ip_gw(dst_ip, user_data->ip4);
     
     route_ip_gw(dst_ip, user_data->ip4);
     */
}


DBFilterResult DBRoutingSystem::route_dns_msg_callback(DBDNSMessage &dns_msg, DBDNSResourceRecord &record, std::shared_ptr<void> user_data)
{
    if (!_route_dns_msg_callback(dns_msg, record, user_data))
        return DBFilterDropRecord;
    return DBFilterAccept;
}

DBFilterResult DBRoutingSystem::resolve_dns_msg_callback(DBDNSMessage &dns_msg, DBDNSQuestionRecord &record, std::shared_ptr<void> user_data)
{
    const std::shared_ptr<if_route_inf_t> &gw_info = std::static_pointer_cast<if_route_inf_t>(user_data);
    char buf[IFNAMSIZ];
    std::cout << "DOPE: " << record.query_type << ") " << record.domain_name() << " -> " << inet_ntoa(gw_info->ip4) << " : " << if_indextoname(gw_info->gw_if, buf) << " " << (gw_info->accept ? "Accept" : "Reject") << "\n";
    if (!gw_info->accept)
        return DBFilterDropQuestion;
    
    std::shared_lock read_lock(resolver_route_shared_mutex);
    
    // Let's do some group based synchronization (In here group id is the interface id)
    {
        std::unique_lock<std::mutex> lock(resolver_route_mutex);
        resolver_route_cv.wait(lock, [gw_info] { return resolver_route_is_reset || resolver_route_owning_interface == gw_info->gw_if || resolver_route_owning_interface_ref_count == 0; });
        
        // If we have reset, then reject the message for a retry
        if (resolver_route_is_reset)
            return DBFilterReject;
        
        // If ref count is 0, send route
        if (resolver_route_owning_interface_ref_count == 0)
        {
            // If we can't route the request, then use the pipeline resolver.
            if (!route_ip_gw(alt_resolve_addr, gw_info->ip4, gw_info->gw_if))
                return DBFilterAccept;
            
            // Set the owning interface
            resolver_route_owning_interface = gw_info->gw_if;
        }
        
        // Increase ref count
        resolver_route_owning_interface_ref_count++;
    }
    
    std::optional<std::unique_ptr<DBDoHResolver> > resolver_opt = resolvers.dequeue();
    if (!resolver_opt.has_value())
        return DBFilterAccept;      // Retry with the pipeline resolver
    
    std::unique_ptr<DBDoHResolver> resolver = std::move(*resolver_opt);
    
    dns_msg = std::move(*(resolver->resolve(dns_msg)));
    
    resolvers.enqueue(std::move(resolver));
    
    // Let's do some group based synchronization (In here group id is the interface id)
    {
        std::unique_lock<std::mutex> lock(resolver_route_mutex);
        
        // Decrease ref count
        resolver_route_owning_interface_ref_count--;
    }
    
    return DBFilterSkipResolve;
}
