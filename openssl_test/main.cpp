//
//  main.cpp
//  openssl_test
//
//  Created by Soroush Faghihi on 8/22/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include <iostream>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/e_os2.h>

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#include <openssl/async.h>

#include "DBDNSMessage.hpp"

#define HOST_NAME "1.1.1.1"
#define HOST_PORT "853"
#define HOST_RESOURCE "/"

/* This prints the Common Name (CN), which is the "friendly" */
/*   name displayed to users in many tools                   */
void print_cn_name(const char* label, X509_NAME* const name)
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "%s: %s\n", label, utf8);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void print_san_name(const char* label, X509* const cert)
{
    int success = 0;
    GENERAL_NAMES* names = NULL;
    unsigned char* utf8 = NULL;
    
    do
    {
        if(!cert) break; /* failed */
        
        names = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0 );
        if(!names) break;
        
        int i = 0, count = sk_GENERAL_NAME_num(names);
        if(!count) break; /* failed */
        
        for( i = 0; i < count; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = -1;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded null?): %d vs %d\n", len2, len1);
                }
                
                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }
                
                if(utf8) {
                    OPENSSL_free(utf8);
                    utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }
        
    } while (0);
    
    if(names)
        GENERAL_NAMES_free(names);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void init_openssl_library(void)
{
    (void)SSL_library_init();
    
    SSL_load_error_strings();
    
    /* ERR_load_crypto_strings(); */
    
    OPENSSL_config(NULL);
    
    /* Include <openssl/opensslconf.h> to get this define */
#if defined (OPENSSL_THREADS)
    fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    print_cn_name("Issuer (cn)", iname);
    print_cn_name("Subject (cn)", sname);
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs too */
        print_san_name("Subject (san)", cert);
    }
    
    return preverify;
}

void handleFailure()
{
    perror("Openssl Failure");
    exit(-1);
}

int main(int argc, const char * argv[])
{
    long res = 1;
    
    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    
    init_openssl_library();
    
    const SSL_METHOD* method = SSLv23_method();
    if(!(NULL != method)) handleFailure();
    
    ctx = SSL_CTX_new(method);
    if(!(ctx != NULL)) handleFailure();
    
    /* Cannot fail ??? */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    /* Cannot fail ??? */
    SSL_CTX_set_verify_depth(ctx, 4);
    
    /* Cannot fail ??? */
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);
    
    res = SSL_CTX_load_verify_locations(ctx, "/usr/local/etc/openssl/cert.pem", NULL);
    if(!(1 == res)) handleFailure();
    
    web = BIO_new_ssl_connect(ctx);
    if(!(web != NULL)) handleFailure();
    
    res = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
    if(!(1 == res)) handleFailure();
    
    BIO_get_ssl(web, &ssl);
    if(!(ssl != NULL)) handleFailure();
    
    const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    if(!(1 == res)) handleFailure();
    
    //res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
    //if(!(1 == res)) handleFailure();
    
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!(NULL != out)) handleFailure();
    
    res = BIO_do_connect(web);
    if(!(1 == res)) handleFailure();
    
    res = BIO_do_handshake(web);
    if(!(1 == res)) handleFailure();
    
    /* Step 1: verify a server certificate was presented during the negotiation */
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) { X509_free(cert); } /* Free immediately */
    if(NULL == cert) handleFailure();
    
    /* Step 2: verify the result of chain verification */
    /* Verification performed according to RFC 4158    */
    res = SSL_get_verify_result(ssl);
    if(!(X509_V_OK == res)) handleFailure();
    
    /* Step 3: hostname verification */
    /* An exercise left to the reader */
    const size_t dns_len = 100;
    array_unique_ptr<uint8_t> dns_s_p(new uint8_t[dns_len]);
    const uint8_t dns_data [] =
    {
        0x0c, 0x6b, 0x01, 0x25, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05, 0x77,
        0x77, 0x66, 0x64, 0x64, 0x05, 0x61, 0x70, 0x70,
        0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    memcpy(dns_s_p.get(), dns_data, sizeof(dns_data));
    
    DBDNSMessage msg{std::move(dns_s_p), sizeof(dns_data), DBDNSMessage::DNSQueryType};
    
    hex_dump_data(msg.bytes_length(true), msg.bytes(true));
    
    BIO_write(web, msg.bytes(true), msg.bytes_length(true));
    
    //BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\n"
    //         "Host: " HOST_NAME "\r\n"
    //         "Connection: close\r\n\r\n");
    //BIO_puts(out, "\n");
    
    int len = 0;
    do
    {
        char buff[1536] = {};
        len = BIO_read(web, buff, sizeof(buff));
        
        if(len > 0)
            hex_dump_data(len, (uint8_t *)buff);
        
    } while (len > 0 || BIO_should_retry(web));
    
    if(out)
        BIO_free(out);
    
    if(web != NULL)
        BIO_free_all(web);
    
    if(NULL != ctx)
        SSL_CTX_free(ctx);
    
    
    while (1) {
        sleep(10);
    }
    
    return 0;
}
