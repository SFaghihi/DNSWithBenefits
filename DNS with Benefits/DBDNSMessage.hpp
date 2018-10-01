//
//  DBDNSMessage.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBDNSMessage_hpp
#define DBDNSMessage_hpp

#include <iostream>
#include <vector>
#include <set>
#include <memory>
#include <string>
#include <string_view>
#include <map>

#include "DBRadixTrie.hpp"
#include "DBUtility.hpp"

// ***************************************************************************
#if 0
#pragma mark - DNS Resource Record class and type constants
#endif

enum DNS_ClassValues                    // From RFC 1035
{
    kDNSClass_IN               = 1,     // Internet
    kDNSClass_CS               = 2,     // CSNET
    kDNSClass_CH               = 3,     // CHAOS
    kDNSClass_HS               = 4,     // Hesiod
    kDNSClass_NONE             = 254,   // Used in DNS UPDATE [RFC 2136]
    
    kDNSClass_Mask             = 0x7FFF, // Multicast DNS uses the bottom 15 bits to identify the record class...
    kDNSClass_UniqueRRSet      = 0x8000, // ... and the top bit indicates that all other cached records are now invalid
    
    kDNSQClass_ANY             = 255,   // Not a DNS class, but a DNS query class, meaning "all classes"
    kDNSQClass_UnicastResponse = 0x8000 // Top bit set in a question means "unicast response acceptable"
};

enum DNS_TypeValues         // From RFC 1035
{
    kDNSType_A = 1,         //  1 Address
    kDNSType_NS,            //  2 Name Server
    kDNSType_MD,            //  3 Mail Destination
    kDNSType_MF,            //  4 Mail Forwarder
    kDNSType_CNAME,         //  5 Canonical Name
    kDNSType_SOA,           //  6 Start of Authority
    kDNSType_MB,            //  7 Mailbox
    kDNSType_MG,            //  8 Mail Group
    kDNSType_MR,            //  9 Mail Rename
    kDNSType_NULL,          // 10 NULL RR
    kDNSType_WKS,           // 11 Well-known-service
    kDNSType_PTR,           // 12 Domain name pointer
    kDNSType_HINFO,         // 13 Host information
    kDNSType_MINFO,         // 14 Mailbox information
    kDNSType_MX,            // 15 Mail Exchanger
    kDNSType_TXT,           // 16 Arbitrary text string
    kDNSType_RP,            // 17 Responsible person
    kDNSType_AFSDB,         // 18 AFS cell database
    kDNSType_X25,           // 19 X_25 calling address
    kDNSType_ISDN,          // 20 ISDN calling address
    kDNSType_RT,            // 21 Router
    kDNSType_NSAP,          // 22 NSAP address
    kDNSType_NSAP_PTR,      // 23 Reverse NSAP lookup (deprecated)
    kDNSType_SIG,           // 24 Security signature
    kDNSType_KEY,           // 25 Security key
    kDNSType_PX,            // 26 X.400 mail mapping
    kDNSType_GPOS,          // 27 Geographical position (withdrawn)
    kDNSType_AAAA,          // 28 IPv6 Address
    kDNSType_LOC,           // 29 Location Information
    kDNSType_NXT,           // 30 Next domain (security)
    kDNSType_EID,           // 31 Endpoint identifier
    kDNSType_NIMLOC,        // 32 Nimrod Locator
    kDNSType_SRV,           // 33 Service record
    kDNSType_ATMA,          // 34 ATM Address
    kDNSType_NAPTR,         // 35 Naming Authority PoinTeR
    kDNSType_KX,            // 36 Key Exchange
    kDNSType_CERT,          // 37 Certification record
    kDNSType_A6,            // 38 IPv6 Address (deprecated)
    kDNSType_DNAME,         // 39 Non-terminal DNAME (for IPv6)
    kDNSType_SINK,          // 40 Kitchen sink (experimental)
    kDNSType_OPT,           // 41 EDNS0 option (meta-RR)
    kDNSType_APL,           // 42 Address Prefix List
    kDNSType_DS,            // 43 Delegation Signer
    kDNSType_SSHFP,         // 44 SSH Key Fingerprint
    kDNSType_IPSECKEY,      // 45 IPSECKEY
    kDNSType_RRSIG,         // 46 RRSIG
    kDNSType_NSEC,          // 47 Denial of Existence
    kDNSType_DNSKEY,        // 48 DNSKEY
    kDNSType_DHCID,         // 49 DHCP Client Identifier
    kDNSType_NSEC3,         // 50 Hashed Authenticated Denial of Existence
    kDNSType_NSEC3PARAM,    // 51 Hashed Authenticated Denial of Existence
    
    kDNSType_HIP = 55,      // 55 Host Identity Protocol
    
    kDNSType_SPF = 99,      // 99 Sender Policy Framework for E-Mail
    kDNSType_UINFO,         // 100 IANA-Reserved
    kDNSType_UID,           // 101 IANA-Reserved
    kDNSType_GID,           // 102 IANA-Reserved
    kDNSType_UNSPEC,        // 103 IANA-Reserved
    
    kDNSType_TKEY = 249,    // 249 Transaction key
    kDNSType_TSIG,          // 250 Transaction signature
    kDNSType_IXFR,          // 251 Incremental zone transfer
    kDNSType_AXFR,          // 252 Transfer zone of authority
    kDNSType_MAILB,         // 253 Transfer mailbox records
    kDNSType_MAILA,         // 254 Transfer mail agent records
    kDNSQType_ANY           // Not a DNS type, but a DNS query type, meaning "all types"
};

enum DNS_RCODEValues
{
    kDNSRCODE_NoError = 0,
    kDNSRCODE_FormErr,
    kDNSRCODE_ServFail,
    kDNSRCODE_NXDomain,
    kDNSRCODE_NotImp,
    kDNSRCODE_Refused
};

std::string DNSClass_to_string(uint16_t cls);
const std::string &DNSType_to_string(uint16_t type);
std::string DNSRCODE_to_string(uint16_t rcode);

class DBDNSQuestionRecord
{
    friend class DBDNSMessage;
    uint16_t _index;
    std::string _domain_name;
    std::unique_ptr<std::map<std::string, void *> > tag_map;
    
public:
    const std::string &domain_name() const;
    uint16_t query_type;
    uint16_t query_class;
    
    DBDNSQuestionRecord(std::string name, uint16_t type, uint16_t cls);
    
    DBDNSQuestionRecord(const DBDNSQuestionRecord& record);
    DBDNSQuestionRecord &operator=(DBDNSQuestionRecord&& record);
    
    DBDNSQuestionRecord(DBDNSQuestionRecord&& record);
    DBDNSQuestionRecord &operator=(const DBDNSQuestionRecord& record);
    
    friend std::ostream& operator<<(std::ostream& os, const DBDNSQuestionRecord &question);
};

class DBDNSResourceRecord
{
    friend class DBDNSMessage;
    uint16_t _index;
    std::string _domain_name;
    std::shared_ptr<uint8_t> data_ptr;
    std::unique_ptr<std::map<std::string, void *> > tag_map;
    
public:
    uint16_t query_type;
    uint16_t query_class;
    uint32_t ttl;
    uint16_t data_length;
    uint8_t *data();
    const uint8_t *data() const;
    const std::string &domain_name() const;
    
public:
    DBDNSResourceRecord(std::string name, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t data_length, const uint8_t *rdata);
    
    DBDNSResourceRecord(const DBDNSResourceRecord& record);
    DBDNSResourceRecord(DBDNSResourceRecord&& record);
    
    DBDNSResourceRecord &operator=(DBDNSResourceRecord&& record);
    DBDNSResourceRecord &operator=(const DBDNSResourceRecord& record);
    
    friend std::ostream& operator<<(std::ostream& os, const DBDNSResourceRecord &record);
};

class DBReadBuffer;
class DBWriteBuffer;

class DBDNSMessage
{
    friend class DBPreFilteringSystem;
    friend class DBPostFilteringSystem;
    friend class DBResolverHTTPHandler;
    
    static constexpr bool debug_dns_message = false;
    
    std::unique_ptr<std::map<std::string, void *> > tag_map;
    
    const uint16_t output_cache_size = 8096;
    const uint32_t EDNS_VERSION_0 = 0;
    
    std::vector<DBDNSQuestionRecord> question_records;
    std::vector<DBDNSResourceRecord> answer_records;
    std::vector<DBDNSResourceRecord> auth_records;
    std::vector<DBDNSResourceRecord> additional_records;
    std::set<uint16_t, std::greater<uint16_t> > deleted_questions_idx;
    std::set<uint16_t, std::greater<uint16_t> > deleted_answers_idx;
    
    bool _is_good = false;
    bool _is_edns = false;
    DBDNSResourceRecord *OPT_record = nullptr;
    
    struct dns_header_t {
        uint16_t identification;
        uint16_t control;
        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t additional_count;
    } dns_header;
    
    mutable array_unique_ptr<uint8_t> output_data_ptr;
    mutable size_t output_data_size = 0;
    
    inline bool populate_questions(DBReadBuffer &data_buf);
    inline bool populate_records(DBReadBuffer &data_buf, std::vector<DBDNSResourceRecord> &records, uint16_t record_count);
    inline void write_records(const std::vector<DBDNSResourceRecord> &records, DBWriteBuffer &output_buffer) const;
    
    void delete_all_records();
    
    void create_output() const;
    
public:
    enum DNSMessageType : bool {
        DNSQueryType = false,
        DNSResponseType = true
    };
    
    DBDNSMessage(std::shared_ptr<const uint8_t> data, size_t data_length, DNSMessageType type);
    
    DBDNSMessage(const DBDNSMessage &message);
    DBDNSMessage(DBDNSMessage &&message);
    
    DBDNSMessage &operator=(const DBDNSMessage &message);
    DBDNSMessage &operator=(DBDNSMessage &&message);
    
    
    DNSMessageType message_type() const;
    uint16_t identification() const;
    
    bool is_good() const;
    
    std::vector<DBDNSQuestionRecord> &questions();
    std::vector<DBDNSResourceRecord> &answers();
    std::vector<DBDNSResourceRecord> &authorities();
    std::vector<DBDNSResourceRecord> &additionals();
    
    const std::vector<DBDNSQuestionRecord> &questions()   const;
    const std::vector<DBDNSResourceRecord> &answers()     const;
    const std::vector<DBDNSResourceRecord> &authorities() const;
    const std::vector<DBDNSResourceRecord> &additionals() const;
    
    void delete_record(const DBDNSResourceRecord &record);
    void delete_record(const DBDNSQuestionRecord &record);
    
    unsigned short question_count()   const;
    unsigned short answer_count()     const;
    unsigned short auth_count()       const;
    unsigned short additional_count() const;
    
    const uint8_t *bytes(bool tcp_guard = false) const;
    size_t bytes_length(bool tcp_guard = false) const;
    
    void set_type(bool type);
    void set_RCODE(uint16_t code);
    
    void hex_dump(std::ostream &o = std::cout, int char_per_line = 8, bool tcp_guard = false) const;
    
    friend std::ostream& operator<<(std::ostream& os, const DBDNSMessage &message);
};

#endif /* DBDNSMessage_hpp */
