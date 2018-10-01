//
//  DBDoTResolver.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/22/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBDoTResolver.hpp"
#include "Exception.hpp"

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/e_os2.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <openssl/async.h>

/************************** Start of DBDoTResolver *****************************/

// Statics
CRYPTO_ONCE global_openssl_has_init_once = CRYPTO_ONCE_STATIC_INIT;

void global_init_openssl()
{
    (void)SSL_library_init();
    
    SSL_load_error_strings();
    
    ERR_load_crypto_strings();
    
    //OPENSSL_config(NULL);
    
    /* Include <openssl/opensslconf.h> to get this define */
//#if defined (OPENSSL_THREADS)
//    fprintf(stdout, "Warning: thread locking is not implemented\n");
//#endif
}

void DBDoTResolver::init_openssl()
{
    CRYPTO_THREAD_run_once(&global_openssl_has_init_once, &global_init_openssl);
}

// Private
bool DBDoTResolver::connect(size_t &depth, size_t max_depth)
{
    long res = BIO_do_handshake(ssl_bio);
    
    if (res == 1)
    {
        BIO_get_fd(con_bio, &tcp_sock_fd);
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
            if (kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout))
                throw Exception("Kevent said Nope!!!!");
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
            if (kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout))
                throw Exception("Kevent said Nope!!!!");
        }
        unsigned long err = ERR_get_error();
        std::cout << "TLS Error: proc_write_nb! ( " << err << " ) Attempting reset!\n";
        if(err)
        {
            std::cout << "SSL connect err code:[" << err << "](" << ERR_error_string(err, NULL) << ")\n";
            std::cout << "Error is " << ERR_reason_error_string(err) << "\n";
        }
        
        std::cout << "TLS SUCCESS: connect! ( fd = " << tcp_sock_fd << " )!\n";
        return true;
    }
    else if (BIO_should_retry(con_bio))
    {
        /*while (res != 1)
        {
            short event = BIO_should_read(ssl_bio) ? POLLIN : POLLOUT;
            
            pollfd pfd = { tcp_sock_fd, event, 0};
            
            int pres = poll(&pfd, 1, -1);
            if (pres == -1)
                throw Exception("Poll error");
            
            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
            {
                std::cout << "TLS Error: proc_write! Attempting reset!\n";
                return reset(depth, max_depth);
            }
            
            res = BIO_do_handshake(ssl_bio);
        }*/
        BIO_get_fd(con_bio, &tcp_sock_fd);
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
            if (kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout))
                throw Exception("Kevent said Nope!!!!");
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
            if (kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout))
                throw Exception("Kevent said Nope!!!!");
        }
    }
    else
    {
        std::cout << "TLS Error: connect! ( " << ERR_get_error() << " ) Attempting reset!\n";
        if (depth < max_depth)
        {
            depth++;
            return reset(depth, max_depth);
        }
    }
    
    return false;
}

/*bool DBDoTResolver::tcp_open_connect(bool should_block)
{
    long res;
    
    if (in_connection_progress)
    {
        pollfd pfds[1] =
        {
            { tcp_sock_fd, POLLOUT, 0}
        };
        
        res = poll(pfds, 1, should_block ? -1 : 0);
        if (res == -1)
            throw Exception("Poll error");
        
        if (res == 0)
            return false;
        
        goto SOCK_BIO_INIT;
    }
    
    /*************** Network Cleanup *************** /
    if (tcp_sock_fd != -1)
    {
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        }
    }
    if (con_bio != nullptr)
    {
        BIO_reset(con_bio);
        BIO_get_fd(con_bio, &tcp_sock_fd);
    }
    
    /************* Network Socket Initialization ************* /
    /*tcp_sock_fd = socket(resolver_addr->sa_family, SOCK_STREAM, 0);
    if (tcp_sock_fd == -1) { std::cout << "TCP Error: Socket Creation!\n"; return false; }
    
    res = fcntl (tcp_sock_fd, F_SETFL, O_NONBLOCK);
    if (res == -1) { std::cout << "TCP Error: fcntl set O_NONBLOCK!\n"; return false; }
    
    res = setsockopt(tcp_sock_fd, SOL_SOCKET, SO_KEEPALIVE, &so_keepalive_flag, sizeof(so_keepalive_flag));
    if (res != 0) { std::cout << "TCP Error: SetSockOpt SO_KEEPALIVE!\n"; return false; }
    
    res = setsockopt(tcp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &so_reuse_flag, sizeof(so_reuse_flag));
    if (res != 0) { std::cout << "TCP Error: SetSockOpt SO_REUSEADDR!\n"; return false; }
    
    res = setsockopt(tcp_sock_fd, SOL_SOCKET, SO_NOSIGPIPE, &so_nosigpipe_flag, sizeof(so_nosigpipe_flag));
    if (res != 0) { std::cout << "TCP Error: SetSockOpt SO_NOSIGPIPE!\n"; return false; }* /
    
    /* Connect to resolver * /
    res = connect(tcp_sock_fd, resolver_addr.get(), resolver_addr->sa_len);
    if (res == 0 || errno == EINPROGRESS)
    {
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        }
    }
    if (res != 0)
    {
        if (errno == EINPROGRESS)
        {
            if (should_block)
            {
                pollfd pfds[1] =
                {
                    { tcp_sock_fd, POLLOUT, 0}
                };
                
                int res;
                
                res = poll(pfds, 1, -1);
                if (res == -1)
                    throw Exception("Poll error");
                
                if (res == 0)
                    return false;
                
                goto SOCK_BIO_INIT;
            }
            else
            {
                in_connection_progress = true;
                return false;
            }
        }
        
        std::cout << "TCP Error: Socket Connection!\n";
        return false;
    }
    
SOCK_BIO_INIT:
    long sock_err = 0; socklen_t sock_err_len = sizeof(sock_err);
    getsockopt(tcp_sock_fd, SOL_SOCKET, SO_ERROR, (void *)&sock_err, &sock_err_len);
    if (sock_err)
        throw Exception("Sock Async Error: " + std::to_string(sock_err));
    
    in_connection_progress = false;
    return true;
}*/

/*bool DBDoTResolver::tls_perform_handshake(bool should_block)
{
    /************** TLS Handshake ************* /
    int handshake_res;
    while ((handshake_res = SSL_do_handshake(ssl)) != 1)
    {
        short event;
        int err = SSL_get_error(ssl, handshake_res);
        switch (err)
        {
            case SSL_ERROR_WANT_READ:
                if (!should_block)
                    return false;
                event = POLLIN;
                break;
            
            case SSL_ERROR_WANT_WRITE:
                if (!should_block)
                    return false;
                event = POLLOUT;
                break;
            
            default:
                //ERR_print_errors(outbio);
                std::cout << "TLS Error: SSL BIO Do Handshake! ( SSL Error: " << err << " ) Attempting reset!\n";
                perror("SYSCAL?");
                reset(should_block);
                return false;
        }
        
        
        pollfd pfds = { tcp_sock_fd, event, 0 };
        
        int pres = poll(&pfds, 1, -1);
        if (pres == -1)
            throw Exception("Poll error");
        
        if (pfds.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            long sock_err = 0; socklen_t sock_err_len = sizeof(sock_err);
            int gsres = getsockopt(tcp_sock_fd, SOL_SOCKET, SO_ERROR, (void *)&sock_err, &sock_err_len);
            if (sock_err || gsres)
            {
                std::cout << "TLS Error: SSL BIO Do Handshake! (Socket Error:" << sock_err << ") Attempting reset!\n";
                reset(should_block);
                return false;
            }
        }
    }
    
    /* Step 1: verify a server certificate was presented during the negotiation * /
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) { X509_free(cert); } /* Free immediately * /
    if (cert == nullptr) { std::cout << "TLS Error: NO Certificate presented during negotiation!\n"; return false; }
    
    /* Step 2: verify the result of chain and hostname verification * /
    /* Verification performed according to RFC 4158    * /
    long res = SSL_get_verify_result(ssl);
    if (res != X509_V_OK) { std::cout << "TLS Error: Presented Certificate failed verification!\n"; return false; }
    
    return true;
}*/

long mine_cb (BIO *b, int oper, const char *argp,
size_t len, int argi,
long argl, int ret, size_t *processed)
{
    if (oper & (BIO_CB_WRITE | BIO_CB_RETURN))
    {
        if (ret==1 && processed && *processed != 0)
        {
            size_t minl = *processed;
            if (len < minl)
                minl = len;
            std::cout << "Bio: " << BIO_method_name(b) << " ";
            std::cout << "TLS WRITE (ret: " << ret << ")"  << "Len: " << minl << "\n";
            //std::cout << " { \n";
            //hex_dump_data(minl, (const uint8_t *)argp, std::cout, 16);
            //std::cout << "\n}\n";
        }
        else
        {
            unsigned long err = ERR_get_error();
            if (err)
            {
                std::cout << "Bio: " << BIO_method_name(b) << " ";
                std::cout << "TLS WRITE (ret: " << ret << ")";
                std::cout << " { \n";
                std::cout << "SSL connect err code:[" << err << " ( " << ERR_error_string(err, NULL) << " )\n";
                std::cout << "Error is " << ERR_reason_error_string(err);
                std::cout << "\n}\n";
            }
        }
        
    }
    else if (oper & (BIO_CB_READ | BIO_CB_RETURN))
    {
        if (ret==1 && processed && *processed != 0)
        {
            size_t minl = *processed;
            if (len < minl)
                minl = len;
            std::cout << "Bio: " << BIO_method_name(b) << " ";
            std::cout << "TLS READ (ret: " << ret << ")" << "Len: " << minl;
            std::cout << " { \n";
            hex_dump_data(minl, (const uint8_t *)argp, std::cout, 16);
            std::cout << "}\n";
        }
        else
        {
            unsigned long err = ERR_get_error();
            if (err)
            {
                std::cout << "Bio: " << BIO_method_name(b) << " ";
                std::cout << "TLS READ (ret: " << ret << ")";
                std::cout << " { \n";
                std::cout << "SSL connect err code:[" << err << " ( " << ERR_error_string(err, NULL) << " )\n";
                std::cout << "Error is " << ERR_reason_error_string(err);
                std::cout << "\n}\n";
            }
        }
    }
    
    return ret;
}

// Constructor
inline void handleFailure(const std::string &e = "") { throw Exception("OpenSSL Error during construction of DBDoTResolver (" + e + ")"); }

DBDoTResolver::DBDoTResolver(int _kq, const sockaddr *_resolver_addr, const std::string &verify_hostname, const std::string &ca_path)
: resolver_addr((sockaddr *)malloc(_resolver_addr->sa_len)), hostname(verify_hostname), kq(_kq)
{
    memcpy(resolver_addr.get(), _resolver_addr, _resolver_addr->sa_len);
    long res = -1;
    
    /************* Context Initialization **************/
    const SSL_METHOD* method = SSLv23_client_method();
    if (method == nullptr) handleFailure("METHOD");
    
    ctx = SSL_CTX_new(method);
    if (ctx == nullptr) handleFailure("New CTX");
    
    /* These apparantly cannot fail ?! */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, ssl_ctx_flags);
    
    res = SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), NULL);
    if (res != 1) handleFailure("CA Path: " + ca_path);
    
    res = SSL_CTX_set_cipher_list(ctx, SSL_ctx_v1_2_cipphers);
    if(!(1 == res)) handleFailure("CTX TLSv1.2 set cipher");
    
    //res = SSL_CTX_set_ciphersuites(ctx, SSL_ctx_v1_3_cipphers);
    //if(!(1 == res)) handleFailure("CTX TLSv1.3 set cipher");
    
    
    
    /************* SSL BIO Initialization *************/
    ssl_bio = BIO_new_ssl(ctx, 1);
    if (ssl_bio == nullptr) handleFailure("New SSL BIO");
    
    BIO_get_ssl(ssl_bio, &ssl);
    if (ssl == nullptr) handleFailure("SSL_BIO GET SSL");
    
    /* Don't want any retries
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);*/
    SSL_set_connect_state(ssl);
    
    //res = SSL_set_tlsext_host_name(ssl, hostname.c_str());
    //if(!(1 == res)) handleFailure("SSL Set TLS SNI Extension");
    
    SSL_set_hostflags(ssl, ssl_host_flags);
    if (!SSL_set1_host(ssl, hostname.c_str())) handleFailure("SSL Set Hostname");
    
    outbio = BIO_new_fd(STDOUT_FILENO, BIO_NOCLOSE);
    
    BIO_set_callback_ex(ssl_bio, mine_cb);
    //BIO_set_callback_arg(ssl_bio, (char *)outbio);
    
    
    
    /************** BIO Socket Initialization *************/
    BIO_ADDR *res_addr = BIO_ADDR_new();
    switch (resolver_addr->sa_family)
    {
        case AF_INET:
            BIO_ADDR_rawmake(res_addr, AF_INET,
                             &((sockaddr_in *)resolver_addr.get())->sin_addr, sizeof(in_addr_t), ((sockaddr_in *)resolver_addr.get())->sin_port);
            break;
        
        case AF_INET6:
            BIO_ADDR_rawmake(res_addr, AF_INET6,
                             &((sockaddr_in6 *)resolver_addr.get())->sin6_addr, sizeof(in6_addr), ((sockaddr_in6 *)resolver_addr.get())->sin6_port);
            break;
        
        case AF_UNIX:
            BIO_ADDR_rawmake(res_addr, AF_UNIX,
                             ((sockaddr_un *)resolver_addr.get())->sun_path, strlen(((sockaddr_un *)resolver_addr.get())->sun_path), 0);
            break;
            
        default:
            break;
    }
    con_bio = BIO_new(BIO_s_connect());
    if (con_bio == nullptr) handleFailure("TCP Error: Connect BIO Creation!\n");
    
    BIO_set_conn_address(con_bio, res_addr);
    BIO_set_nbio(con_bio, so_nb_flag);
    
    BIO_set_callback_ex(con_bio, mine_cb);
    //BIO_set_callback_arg(con_bio, (char *)outbio);
    
    BIO_get_fd(con_bio, &tcp_sock_fd);
    BIO_push(ssl_bio, con_bio);
    
    reset_once();
    
    /************** TCP Handshake *************/
    //if (!tcp_open_connect(true)) handleFailure("TCP HandShake");
    
    /************** TLS Handshake *************/
    //if (!tls_perform_handshake(true)) handleFailure("TLS HandShake");
}

DBDoTResolver::DBDoTResolver(DBDoTResolver &&r)
: ctx(r.ctx), ssl_bio(r.ssl_bio),
con_bio(r.con_bio), ssl(r.ssl),
hostname(std::move(r.hostname)),

// Networking Stuff
in_connection_progress(r.in_connection_progress),
tcp_sock_fd(r.tcp_sock_fd),
resolver_addr(std::move(r.resolver_addr)),

kq(r.kq),

// Buffering Stuff
dns_tcp_length(r.dns_tcp_length), dns_tcp_len_read(r.dns_tcp_len_read),
read_message_buffer(std::move(r.read_message_buffer)),
read_message_length(r.read_message_length), read_message_idx(r.read_message_idx),
send_message_buffers(std::move(r.send_message_buffers))
{
    r.ctx = nullptr; r.ssl_bio = nullptr;
    r.con_bio = nullptr; r.ssl = nullptr;
    r.read_message_length = 0; r.read_message_idx = 0;
    r.dns_tcp_length = 0; r.dns_tcp_len_read = 0;
}

DBDoTResolver::~DBDoTResolver()
{
    if (tcp_sock_fd != -1)
    {
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        }
    }
    
    if (ctx != nullptr)
        SSL_CTX_free(ctx);
    
    if (ssl_bio != nullptr)
        BIO_free(ssl_bio);
    
    if (con_bio != nullptr)
        BIO_free(con_bio);
    
    if (outbio != nullptr)
        BIO_free(outbio);
}


// Public
int DBDoTResolver::get_sock_fd() const { return tcp_sock_fd; }

bool DBDoTResolver::reset_once()
{
    size_t depth = 0, max_depth = 1;
    return reset(depth, max_depth);
}

bool DBDoTResolver::reset(size_t &depth, size_t max_depth)
{
    read_message_buffer.reset();
    read_message_idx = 0; read_message_length = 0;
    dns_tcp_length = 0; dns_tcp_len_read = 0;
    
    if (!SSL_in_init(ssl))
        SSL_shutdown(ssl);
    
    SSL_clear(ssl);
    
    if (tcp_sock_fd != -1)
    {
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        }
    }
    
    if (con_bio != nullptr)
    {
        BIO_reset(con_bio);
        
        BIO_get_fd(con_bio, &tcp_sock_fd);
    }
    
    return connect(depth, max_depth);
    //return tcp_open_connect(should_block);
}

// Resolve Interface
void DBDoTResolver::resolve_nb(const DBDNSMessage *message)
{
    message->hex_dump();
    send_message_buffers.push_back(message);
}

std::unique_ptr<DBDNSMessage> DBDoTResolver::resolve(DBDNSMessage &request)
{
    const DBDNSMessage *request_ptr = &request;
    resolve_nb(request_ptr);
    bool should_retry = true;
    std::list<const DBDNSMessage *> write_list;
    while (should_retry && (write_list.size() == 0))
        write_list = proc_write(should_retry);
    
    if (should_retry)
        proc_write_nb(should_retry);
    
    if (write_list.size())
    {
        std::list<std::unique_ptr<DBDNSMessage>> read_list;
        while (should_retry && (read_list.size() == 0))
            read_list = proc_read(should_retry);
        
        if (should_retry)
            proc_read_nb(should_retry);
        
        if (read_list.size())
            return std::move(read_list.front());
    }
    
    return {};
}

// Blocking I/O
std::list<const DBDNSMessage *> DBDoTResolver::proc_write(bool &should_retry)
{
    should_retry = false;
    std::list<const DBDNSMessage *> sent_messages;
    if (send_message_buffers.size() == 0)
    {
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        }
        return sent_messages;
    }
    
    const DBDNSMessage *current_msg = send_message_buffers.front();
    int res;
    do
    {
        size_t written_num;
        res = BIO_write_ex(ssl_bio, current_msg->bytes(true), current_msg->bytes_length(true), &written_num);
        if (res == 1)
        {
            sent_messages.push_back(current_msg);
            send_message_buffers.pop_front();
            
            if (send_message_buffers.size() == 0)
            {
                if (kq != -1)
                {
                    struct kevent setEnv;
                    EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
                    kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
                }
                break;
            }
            current_msg = send_message_buffers.front();
            continue;
        }
        
        if (!BIO_should_retry(ssl_bio))
        {
            std::cout << "TLS Error: proc_write! Attempting reset!\n";
            if (!reset_once())
            {
                should_retry = true;
                break;
            }
        }
        
        short event = BIO_should_read(ssl_bio) ? POLLIN : POLLOUT;
        if (event & POLLOUT)
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
        else if (event & POLLIN)
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
        
        pollfd pfd = { tcp_sock_fd, event, 0};
        
        int pres = poll(&pfd, 1, -1);
        if (pres == -1)
            throw Exception("Poll error");
        
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            std::cout << "TLS Error: proc_write! Attempting reset!\n";
            if (!reset_once())
            {
                should_retry = true;
                break;
            }
        }
        
        res = 1;
    }
    while (res == 1);
    
    return sent_messages;
}


std::list<std::unique_ptr<DBDNSMessage>> DBDoTResolver::proc_read(bool &should_retry)
{
    should_retry = false;
    std::list<std::unique_ptr<DBDNSMessage>> read_messages;
    
    int res;
    do
    {
        size_t read_length = 0;
        if (read_message_buffer)
        {
            res = BIO_read_ex(ssl_bio, read_message_buffer.get() + read_message_idx, read_message_length - read_message_idx, &read_length);
            if (res == 1)
            {
                read_message_idx += read_length;
                if (read_message_idx == read_message_length)
                {
                    read_messages.emplace_front(std::unique_ptr<DBDNSMessage>{new DBDNSMessage(std::move(read_message_buffer), read_message_length, DBDNSMessage::DNSResponseType)});
                    read_message_idx = 0;
                    read_message_length = 0;
                }
            }
        }
        else
        {
            res = BIO_read_ex(ssl_bio, &dns_tcp_length + dns_tcp_len_read, sizeof(dns_tcp_length) - dns_tcp_len_read, &read_length);
            if (res == 1 && read_length == sizeof(dns_tcp_length))
            {
                res = SSL_read_ex(ssl, &dns_tcp_length, sizeof(dns_tcp_length), &read_length);
                read_message_length = ntohs(dns_tcp_length);
                read_message_buffer.reset(new uint8_t[read_message_length]);
                read_message_idx = 0;
            }
            else if (res == 1)
                dns_tcp_len_read += read_length;
        }
        if (res == 1)
            continue;
        
        if (!BIO_should_retry(ssl_bio))
        {
            std::cout << "TLS Error: proc_read! Attempting reset!\n";
            if (!reset_once())
            {
                should_retry = true;
                break;
            }
        }
        
        if (read_messages.size() != 0)
            break;
        
        short event = BIO_should_read(ssl_bio) ? POLLIN : POLLOUT;
        if (event & POLLOUT)
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
        else if (event & POLLIN)
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
        
        pollfd pfd = { tcp_sock_fd, event, 0};
        
        int pres = poll(&pfd, 1, -1);
        if (pres == -1)
            throw Exception("Poll error");
        
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            std::cout << "TLS Error: proc_write! Attempting reset!\n";
            if (!reset_once())
            {
                should_retry = true;
                break;
            }
        }
        
        res = 1;
    }
    while (res == 1);
    
    return read_messages;
}

// Non-Blocking I/O
std::list<const DBDNSMessage *> DBDoTResolver::proc_write_nb(bool &should_retry)
{
    should_retry = false;
    std::list<const DBDNSMessage *> sent_messages;
    if (send_message_buffers.size() == 0)
    {
        if (kq != -1)
        {
            struct kevent setEnv;
            EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
            kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
        }
        return sent_messages;
    }
    
    const DBDNSMessage *current_msg = send_message_buffers.front();
    int res;
    do
    {
        size_t written_num;
        res = BIO_write_ex(ssl_bio, current_msg->bytes(true), current_msg->bytes_length(true), &written_num);
        if (res == 1)
        {
            sent_messages.push_back(current_msg);
            send_message_buffers.pop_front();
            
            if (send_message_buffers.size() == 0)
            {
                if (kq != -1)
                {
                    struct kevent setEnv;
                    EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_DELETE, 0, 0, static_cast<void *>(this));
                    kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
                }
                break;
            }
            current_msg = send_message_buffers.front();
            continue;
        }
        
        if (!BIO_should_retry(ssl_bio))
        {
            unsigned long err = ERR_get_error();
            std::cout << "TLS Error: proc_write_nb! ( " << err << " ) Attempting reset!\n";
            if(err)
            {
                std::cout << "SSL connect err code:[" << err << "](" << ERR_error_string(err, NULL) << ")\n";
                std::cout << "Error is " << ERR_reason_error_string(err) << "\n";
            }
            
            
            if (!reset_once())
            {
                should_retry = true;
                break;
            }
        }
        
        if (!BIO_should_read(ssl_bio))
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
        else
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
    }
    while (res == 1);
    
    return sent_messages;
}

std::list<std::unique_ptr<DBDNSMessage>> DBDoTResolver::proc_read_nb(bool &should_retry)
{
    should_retry = false;
    std::list<std::unique_ptr<DBDNSMessage>> read_messages;
    
    int res;
    do
    {
        size_t read_length = 0;
        if (read_message_buffer)
        {
            res = BIO_read_ex(ssl_bio, read_message_buffer.get() + read_message_idx, read_message_length - read_message_idx, &read_length);
            if (res == 1)
            {
                read_message_idx += read_length;
                if (read_message_idx == read_message_length)
                {
                    read_messages.emplace_front(std::unique_ptr<DBDNSMessage>{new DBDNSMessage(std::move(read_message_buffer), read_message_length, DBDNSMessage::DNSResponseType)});
                    read_message_idx = 0;
                    read_message_length = 0;
                }
            }
        }
        else
        {
            res = BIO_read_ex(ssl_bio, (uint8_t *)(&dns_tcp_length) + dns_tcp_len_read, sizeof(dns_tcp_length) - dns_tcp_len_read, &read_length);
            if (res == 1 && read_length == sizeof(dns_tcp_length))
            {
                res = SSL_read_ex(ssl, &dns_tcp_length, sizeof(dns_tcp_length), &read_length);
                read_message_length = ntohs(dns_tcp_length);
                read_message_buffer.reset(new uint8_t[read_message_length]);
                read_message_idx = 0;
            }
            else if (res == 1)
                dns_tcp_len_read += read_length;
        }
        
        if (res == 1)
            continue;
        
        if (!BIO_should_retry(ssl_bio))
        {
            unsigned long err = ERR_get_error();
            std::cout << "TLS Error: proc_read_nb! ( " << err << " ) Attempting reset!\n";
            if(err)
            {
                std::cout << "SSL connect err code:[" << err << "](" << ERR_error_string(err, NULL) << ")\n";
                std::cout << "Error is " << ERR_reason_error_string(err) << "\n";
            }
            if (!reset_once())
            {
                should_retry = true;
                break;
            }
        }
        
        if (!BIO_should_read(ssl_bio))
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_WRITE, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
        else
        {
            if (kq != -1)
            {
                struct kevent setEnv;
                EV_SET(&setEnv, tcp_sock_fd, EVFILT_READ, EV_ADD, 0, 0, static_cast<void *>(this));
                kevent(kq, &setEnv, 1, nullptr, 0, &imm_timeout);
            }
        }
    }
    while (res == 1);
    
    return read_messages;
}


bool DBDoTResolver::proc_io()
{
    
    return true;
}
