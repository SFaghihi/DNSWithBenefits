//
//  DBDoHResolver.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/19/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBDoHResolver.hpp"

#include <sys/time.h>
#include <openssl/ssl.h>

#include <iostream>
#include <curl/curl.h>

#include "Exception.hpp"
#include "DBCommon.hpp"
#include "DBDNSMessage.hpp"



/************************** Start of DBDoHResolver *****************************/

// Private
inline size_t DBDoHResolver::is_header(const std::string &header, const std::string &buffer)
{
    if (buffer.length() < header.length())
        return -1;
    
    for (size_t i = 0; i < header.length(); i++) {
        if (tolower(header[i]) != tolower(buffer[i]))
            return -1;
    }
    
    return header.length();
}

bool DBDoHResolver::update_code(long http_code)
{
    http_status_code = http_code;
    if (http_code < 400)
        return true;
    
    should_continue = false;
    
    uint16_t RCODE = http_code == 404 ? kDNSRCODE_Refused : kDNSRCODE_FormErr;
    RCODE = http_code >= 500 ? kDNSRCODE_ServFail : RCODE;
    create_error_response(RCODE);
    
    return false;
}

void DBDoHResolver::reinit()
{
    data.reset();
    data_length = -1;
    data_idx = 0;
    data_buffer.clear();
    
    http_status_code = 0;
    
    should_continue = true;
    has_sent = false;
}

void DBDoHResolver::create_error_response(uint16_t RCODE)
{
    if (has_sent)
        return;
    has_sent = true;
    
    response_ptr->set_type(DBDNSMessage::DNSResponseType);
    response_ptr->set_RCODE(RCODE);
}

void DBDoHResolver::create_response()
{
    if (has_sent)
        return;
    has_sent = true;
    
    if (data_length == -1)
    {
        data_length = data_buffer.size();
        data.reset(new uint8_t[data_length]);
        memcpy(data.get(), data_buffer.data(), data_buffer.size());
        data_idx = data_buffer.size();
        data_buffer.clear();
    }
    response_ptr.reset(new DBDNSMessage(std::shared_ptr<const uint8_t>(std::move(data)), data_length, DBDNSMessage::DNSResponseType));
}

size_t DBDoHResolver::header_handler(char *buffer_c, size_t size, size_t nitems, void *userdata)
{
    auto self = static_cast<DBDoHResolver *>(userdata);
    if (!self->should_continue)
        return 0;
    
    size_t buffer_length = size * nitems;
    std::string buffer(buffer_c, buffer_length);
    //std::cout << "Header -> " << buffer;
    
    size_t idx = -1;
    
    // Check if HTTP Status code
    if (!self->http_status_code && (idx = is_header("HTTP/", buffer)) != -1)
    {
        char *endp = buffer_c;
        strtof(buffer.c_str() + idx, &endp);
        long status_code = strtol(endp, &endp, 10);
        return self->update_code(status_code) ? buffer_length : 0;
    }
    
    if ((idx = is_header("Content-Length:", buffer)) != -1) {
        self->data_length = strtol(buffer.c_str() + idx, NULL, 10);
        //std::cout << "Data Length: " << self->data_length << "\n";
    }
    
    return buffer_length;
}

size_t DBDoHResolver::data_handler(char *data_c, size_t size, size_t nmemb, void *userdata)
{
    auto self = static_cast<DBDoHResolver *>(userdata);
    if (!self->should_continue)
        return 0;
    
    if (self->data_length != -1 && !self->data)
    {
        self->data.reset(new uint8_t[self->data_length]);
        memcpy(self->data.get(), self->data_buffer.data(), self->data_buffer.size());
        self->data_idx = self->data_buffer.size();
        self->data_buffer.clear();
    }
    
    size_t buffer_length = size * nmemb;
    if (self->data)
    {
        memcpy(self->data.get() + self->data_idx, data_c, buffer_length);
    }
    else
    {
        self->data_buffer.resize(self->data_idx + buffer_length);
        memcpy(self->data_buffer.data() + self->data_idx, data_c, buffer_length);
    }
    self->data_idx += buffer_length;
    
    return buffer_length;
}

// Constructors
DBDoHResolver::DBDoHResolver(const std::string &resolver_addr)
{
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        throw Exception("Curl error: while initializing easy handle");
        return;
    }
    
    /* Debug Stuff */
    //curl_easy_setopt(easy_handle, CURLOPT_VERBOSE, 1L);
    
    curl_easy_setopt(easy_handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy_handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(easy_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    
    /* enable all supported built-in compressions */
    curl_easy_setopt(easy_handle, CURLOPT_ACCEPT_ENCODING, "");
    
    curl_easy_setopt(easy_handle, CURLOPT_TCP_FASTOPEN, 1L);
    curl_easy_setopt(easy_handle, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(easy_handle, CURLOPT_TCP_KEEPIDLE, 30L);
    curl_easy_setopt(easy_handle, CURLOPT_TCP_KEEPINTVL, 30L);
    //curl_easy_setopt(easy_handle, CURLOPT_EXPECT_100_TIMEOUT_MS, 1L);
    curl_easy_setopt(easy_handle, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(easy_handle, CURLOPT_CONNECTTIMEOUT, 10L);
    
    curl_easy_setopt(easy_handle, CURLOPT_SSL_ENABLE_ALPN, 1L);
    curl_easy_setopt(easy_handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT);
    
    header_list = curl_slist_append(header_list, "Content-Type: application/dns-message");
    header_list = curl_slist_append(header_list, "Accept:");
    header_list = curl_slist_append(header_list, "Expect:");
    curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, header_list);
    
    hosts_list = curl_slist_append(NULL, ("cloudflare-dns.com::" + resolver_addr + ":").c_str());
    
    if (curl_easy_setopt(easy_handle, CURLOPT_CONNECT_TO, hosts_list) != CURLE_OK)
        std::cout << "NOPE CURL IS FUCKING ME!!!!\n";
    
    curl_easy_setopt(easy_handle, CURLOPT_URL, "https://cloudflare-dns.com/dns-query");
    
    curl_easy_setopt(easy_handle, CURLOPT_HEADERFUNCTION, &DBDoHResolver::header_handler);
    curl_easy_setopt(easy_handle, CURLOPT_HEADERDATA, this);
    
    curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, &DBDoHResolver::data_handler);
    curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, this);
    
    curl_easy_setopt(easy_handle, CURLOPT_ERRORBUFFER, error_buf);
}

DBDoHResolver::~DBDoHResolver()
{
    curl_easy_cleanup(easy_handle);
    curl_slist_free_all(hosts_list);
    curl_slist_free_all(header_list);
}

// Public

const char *DBDoHResolver::error() const { return error_buf; }

std::unique_ptr<DBDNSMessage> DBDoHResolver::resolve(const DBDNSMessage &request)
{
    /* size of the POST data */
    curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, request.bytes_length());
    
    /* pass in a pointer to the data - libcurl will not copy */
    curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, request.bytes());
    
    //hex_dump_data(request.bytes_length(), request.bytes(), std::cout, 16);
    
    reinit();
    
    response_ptr.reset(new DBDNSMessage(request));
    
    CURLcode res = curl_easy_perform(easy_handle);
    if (res == CURLE_OK)
    {
        create_response();
    }
    else if (res != CURLE_ABORTED_BY_CALLBACK && res != CURLE_WRITE_ERROR)
    {
        std::cout << "Curl Error Occured: " << curl_easy_strerror(res) << " (" << res << ")" << " -> " << error() << "\n";
        create_error_response(kDNSRCODE_ServFail);
    }
    else
    {
        std::cout << "Curl Error Occured: " << curl_easy_strerror(res) << " (" << res << ")" << " -> " << error() << "\n";
    }
    
    return std::move(response_ptr);
}
