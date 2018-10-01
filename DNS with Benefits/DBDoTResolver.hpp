//
//  DBDoTResolver.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/22/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBDoTResolver_hpp
#define DBDoTResolver_hpp

#include "DBDNSMessage.hpp"
#include "DBUtility.hpp"

#include <optional>
#include <string>
#include <memory>
#include <list>

// Networking stuff
#include <sys/socket.h>
#include <sys/event.h>

// OpenSSL Stuff
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

class DBDoTResolver
{
    // OpenSSL Config Options
    static constexpr long ssl_ctx_flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1;
    static constexpr const char* const SSL_ctx_v1_2_cipphers =  "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";// "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305";
    static constexpr const char* const SSL_ctx_v1_3_cipphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    static constexpr long ssl_host_flags = X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
    
    // Networking Config Options
    static constexpr int so_nb_flag = 1;
    static constexpr int so_reuse_flag = 1;
    static constexpr int so_keepalive_flag = 1;
    static constexpr int so_nosigpipe_flag = 1;
    
    // OpenSSL Stuff
    SSL_CTX* ctx = nullptr;
    BIO *ssl_bio = nullptr, *con_bio = nullptr, *outbio = nullptr;
    SSL *ssl = nullptr;
    std::string hostname;
    
    // Networking Stuff
    bool in_connection_progress = false;
    int tcp_sock_fd = -1;
    unique_sockaddr resolver_addr;
    
    int kq = -1;
    timespec imm_timeout = {0};
    
    // Buffering Stuff
    uint16_t dns_tcp_length = 0; uint8_t dns_tcp_len_read = 0;
    array_unique_ptr<uint8_t> read_message_buffer;
    size_t read_message_length = 0, read_message_idx = 0;
    std::list<const DBDNSMessage *> send_message_buffers;
    
    // Private methods
    //bool tls_perform_handshake(bool should_block);
    //bool tcp_open_connect(bool should_block);
    
public:
    static void init_openssl();
    
    // Construct TLS1.2 context and perform handshake
    DBDoTResolver(int kq, const sockaddr *resolver_addr, const std::string &verify_hostname, const std::string &ca_path = "/usr/local/etc/openssl/cert.pem");
    DBDoTResolver(DBDoTResolver &&resolver);
    ~DBDoTResolver();
    
    // Access underlying socket
    int get_sock_fd() const;
    
    // Resolve Interface
    void resolve_nb(const DBDNSMessage *message); // Non-Blocking
    std::unique_ptr<DBDNSMessage> resolve(DBDNSMessage &request);
    
    // Blocking I/O
    std::list<const DBDNSMessage *> proc_write(bool &should_retry);
    std::list<std::unique_ptr<DBDNSMessage>> proc_read(bool &should_retry);
    
    // Non-Blocking I/O
    bool proc_io();
    std::list<const DBDNSMessage *> proc_write_nb(bool &should_retry);
    std::list<std::unique_ptr<DBDNSMessage>> proc_read_nb(bool &should_retry);
    
    // Check and Renew connection if needed.
    bool reset_once();
    bool reset(size_t &depth, size_t max_depth = 1);
    bool connect(size_t &depth, size_t max_depth = 1);
};



#endif /* DBDoTResolver_hpp */
