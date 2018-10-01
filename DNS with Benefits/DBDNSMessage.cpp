//
//  DBDNSMessage.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/19/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBDNSMessage.hpp"
#include "Exception.hpp"
#include "DBUtility.hpp"

#include <sstream>
#include <iomanip>

#include <arpa/inet.h>

const std::string DBTypeToString[] = {
    "INVALID",
    
    // 1
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT",
    "RP",
    "AFSDB",
    "X25",
    "ISDN",
    "RT",
    "NSAP",
    "NSAP_PTR",
    "SIG",
    "KEY",
    "PX",
    "GPOS",
    "AAAA",
    "LOC",
    "NXT",
    "EID",
    "NIMLOC",
    "SRV",
    "ATMA",
    "NAPTR",
    "KX",
    "CERT",
    "A6",
    "DNAME",
    "SINK",
    "OPT",
    "APL",
    "DS",
    "SSHFP",
    "IPSECKEY",
    "RRSIG",
    "NSEC",
    "DNSKEY",
    "DHCID",
    "NSEC3",
    "NSEC3PARAM",
    
    // 55
    "HIP",
    
    // 99
    "SPF",
    "UINFO",
    "UID",
    "GID",
    "UNSPEC",
    
    // 249
    "TKEY",
    "TSIG",
    "IXFR",
    "AXFR",
    "MAILB",
    "MAILA",
    "ANY"
};


const std::string &DNSType_to_string(uint16_t type)
{
    if (type <= kDNSType_NSEC3PARAM)
        return DBTypeToString[type];
    
    else if (type < kDNSType_HIP)
        return DBTypeToString[0];
    else if (type == kDNSType_HIP)
        return DBTypeToString[type - kDNSType_HIP + kDNSType_NSEC3PARAM + 1];
    
    else if (type < kDNSType_SPF)
        return DBTypeToString[0];
    else if (type <= kDNSType_UNSPEC)
        return DBTypeToString[type - kDNSType_SPF + kDNSType_NSEC3PARAM + 2];
    
    else if (type < kDNSType_TKEY)
        return DBTypeToString[0];
    else if (type <= kDNSQType_ANY)
        return DBTypeToString[type - kDNSType_TKEY + kDNSType_NSEC3PARAM + 2 + 5];
    
    return DBTypeToString[0];
}

std::string DNSClass_to_string(uint16_t cls)
{
    switch (cls)
    {
        case kDNSClass_IN:
            return "IN";
        case kDNSClass_CS:
            return "CS";
        case kDNSClass_CH:
            return "CH";
        case kDNSClass_HS:
            return "HS";
        case kDNSClass_NONE:
            return "NONE";
            
        case kDNSClass_Mask:
            return "Mask";
        case kDNSClass_UniqueRRSet:
            return "UniqueRRSet | UnicastResponse";
            
        case kDNSQClass_ANY:
            return "ANY";
            
        default:
            return "Invalid";
    }
}

std::string DNSRCODE_to_string(uint16_t rcode)
{
    switch (rcode) {
        case kDNSRCODE_NoError:
            return "NoError";
        case kDNSRCODE_FormErr:
            return "FormErr";
        case kDNSRCODE_ServFail:
            return "ServFail";
        case kDNSRCODE_NXDomain:
            return "NXDomain";
        case kDNSRCODE_NotImp:
            return "NotImp";
        case kDNSRCODE_Refused:
            return "Refused";
        default:
            return "UnkownError";
    }
}

/************************** Start of DBReadBuffer *****************************/
#pragma DBReadBuffer

class DBReadBuffer
{
    std::shared_ptr<const uint8_t> data_ptr;
    uint16_t data_length;
    uint16_t data_idx = 0;
    
    void _read_dns_string(std::stringstream &ss);
    
public:
    DBReadBuffer(std::shared_ptr<const uint8_t> data, uint16_t length);
    DBReadBuffer(DBReadBuffer &&buf);
    DBReadBuffer(const DBReadBuffer &buf);
    
    template<typename D> D read_scalar();
    const uint8_t *read_ptr_at_index(uint16_t idx = 0);
    const uint8_t *read_ptr_at_current_pos(uint16_t length);
    std::string read_dns_string();
};

// Private
void DBReadBuffer::_read_dns_string(std::stringstream &ss)
{
    uint8_t label = read_scalar<uint8_t>();
    while (label != 0)
    {
        if (label <= 0x3F)
        {
            ss.write((const char *)read_ptr_at_current_pos(label), label);
        }
        else if (label >= 0xC0)
        {
            data_idx--;
            uint16_t comp_label = ntohs(read_scalar<uint16_t>());
            size_t old_idx = data_idx;
            data_idx = comp_label & 0x3FFF;
            _read_dns_string(ss);
            data_idx = old_idx;
            break;
        }
        else
        {
            throw Exception("Unknown DNS String Label.");
        }
        label = read_scalar<uint8_t>();
        if (label)
            ss << '.';
    }
}

// Constructors
DBReadBuffer::DBReadBuffer(std::shared_ptr<const uint8_t> data, uint16_t length)
: data_ptr(data), data_length(length)
{}

DBReadBuffer::DBReadBuffer(DBReadBuffer &&buf)
: data_ptr(std::move(buf.data_ptr)), data_length(buf.data_length)
{
    buf.data_length = 0;
}

DBReadBuffer::DBReadBuffer(const DBReadBuffer &buf)
: data_ptr(buf.data_ptr), data_length(buf.data_length)
{}

// Public
template<typename D>
D DBReadBuffer::read_scalar()
{
    if (data_idx >= data_length) {
        throw Exception("Buffer Read index outside bounds.");
    }
    D value = *(D *)(data_ptr.get() + data_idx);
    data_idx += sizeof(D);
    return value;
}

const uint8_t *DBReadBuffer::read_ptr_at_index(uint16_t idx)
{
    if (idx >= data_length) {
        throw Exception("Buffer Read index outside bounds.");
    }
    return data_ptr.get() + idx;
}

const uint8_t *DBReadBuffer::read_ptr_at_current_pos(uint16_t length)
{
    if (data_idx + length > data_length) {
        throw Exception("Buffer Read index outside bounds.");
    }
    const uint8_t *ret_val = data_ptr.get() + data_idx;
    data_idx += length;
    return ret_val;
}

std::string DBReadBuffer::read_dns_string()
{
    std::stringstream ss;
    _read_dns_string(ss);
    return ss.str();
}



/************************** Start of DBWriteBuffer *****************************/

class DBWriteBuffer
{
    array_unique_ptr<uint8_t> data_ptr;
    uint16_t data_length;
    uint16_t data_idx = 0;
    std::unique_ptr<std::map<std::string, uint16_t>> comp_map_ptr;
    
public:
    DBWriteBuffer(uint16_t length);
    DBWriteBuffer(DBWriteBuffer &&buf);
    DBWriteBuffer(const DBWriteBuffer &buf);
    
    uint16_t size();
    uint16_t capacity();
    
    template<typename D>void write_scalar(D value);
    uint8_t *write_ptr_at_index(size_t idx = 0);
    uint8_t *write_ptr_at_current_pos(uint16_t length);
    void write_dns_string(std::string domain_name_str);
    
    array_unique_ptr<uint8_t> take_ownership()
    {
        comp_map_ptr.reset();
        data_idx = 0;
        data_length = 0;
        return std::move(data_ptr);
    }
    
    void print_comp_state(std::ostream &os = std::cout)
    {
        if (!comp_map_ptr)
        {
            os << "Empty Compression State!!!\n";
            return;
        }
        os << "Compression Table:\n" << "Index -> String\n";
        for (auto &t : *comp_map_ptr)
        {
            if (comp_map_ptr->count(t.first))
                os << t.second << "\t->\t" << t.first << "\n";
        }
        os << "-----------------\n";
    }
};


// Constructors
DBWriteBuffer::DBWriteBuffer(uint16_t length)
: data_ptr(new uint8_t[length]), data_length(length)
{}

DBWriteBuffer::DBWriteBuffer(DBWriteBuffer &&buf)
: data_ptr(std::move(buf.data_ptr)), data_length(buf.data_length),
comp_map_ptr(std::move(buf.comp_map_ptr))
{
    buf.data_length = 0;
}

DBWriteBuffer::DBWriteBuffer(const DBWriteBuffer &buf)
: data_ptr(new uint8_t[buf.data_length]), data_length(buf.data_length),
comp_map_ptr(new std::map<std::string, uint16_t>(*buf.comp_map_ptr))
{
    memcpy(data_ptr.get(), buf.data_ptr.get(), buf.data_length);
}

// Public
uint16_t DBWriteBuffer::size() { return data_idx; }
uint16_t DBWriteBuffer::capacity() { return data_length; }

template<typename D>
void DBWriteBuffer::write_scalar(D value)
{
    if (data_idx >= data_length) {
        throw Exception("Buffer Write index outside bounds.");
    }
    *(D *)(data_ptr.get() + data_idx) = value;
    data_idx += sizeof(D);
}

uint8_t *DBWriteBuffer::write_ptr_at_index(size_t idx)
{
    if (idx >= data_length) {
        throw Exception("Buffer Write index outside bounds.");
    }
    return data_ptr.get() + idx;
}

uint8_t *DBWriteBuffer::write_ptr_at_current_pos(uint16_t length)
{
    if (data_idx + length > data_length) {
        throw Exception("Buffer Write index outside bounds.");
    }
    uint8_t *ret_val = data_ptr.get() + data_idx;
    data_idx += length;
    return ret_val;
}

void DBWriteBuffer::write_dns_string(std::string domain_name_str)
{
    if (!comp_map_ptr)
        comp_map_ptr.reset(new std::map<std::string, uint16_t>());
    std::map<std::string, uint16_t> &comp_map = *comp_map_ptr;
    
    std::string_view domain_name = domain_name_str;
    size_t label_start = 0, label_end = 0;
    
    while (label_start < domain_name_str.length())
    {
        std::string ds (domain_name.data(), domain_name.size());
        if (comp_map.count(ds) > 0)
        {
            write_scalar<uint16_t>(htons(comp_map[ds] | 0xC000));
            return;
        }
        comp_map[ds] = data_idx - 2; // Remember the TCP 2 Byte Size
        
        label_end = label_start;
        while (label_end < domain_name_str.length() && domain_name_str[label_end] != '.')
            label_end++;
        
        uint8_t label_length = 0x3F & (label_end - label_start);
        write_scalar<uint8_t>(label_length);
        memcpy(write_ptr_at_current_pos(label_length), domain_name.data(), label_length);
        
        label_start = label_end + 1;
        if (label_end == domain_name_str.length())
            break;
        domain_name = domain_name.substr(label_length + 1, std::string_view::npos);
    }
    write_scalar<uint8_t>(0);
}


/************************** Start of DBDNSQuestionRecord *****************************/

// Private

// Constructors
DBDNSQuestionRecord::DBDNSQuestionRecord(std::string name, uint16_t type, uint16_t cls)
: _domain_name(name), query_type(type), query_class(cls)
{}

DBDNSQuestionRecord::DBDNSQuestionRecord(const DBDNSQuestionRecord& record)
: _domain_name(record._domain_name), query_type(record.query_type), query_class(record.query_class), _index(record._index)
{
    if (record.tag_map)
        tag_map.reset(new std::map<std::string, void *>(*record.tag_map));
}

DBDNSQuestionRecord::DBDNSQuestionRecord(DBDNSQuestionRecord&& record)
: _domain_name(std::move(record._domain_name)), query_type(record.query_type), query_class(record.query_class), tag_map(std::move(record.tag_map)), _index(record._index)
{}

DBDNSQuestionRecord &DBDNSQuestionRecord::operator=(DBDNSQuestionRecord&& record)
{
    if (this == &record)
        return *this;
    
    tag_map = std::move(record.tag_map);
    _domain_name = std::move(record._domain_name);
    query_type = record.query_type;
    query_class = record.query_class;
    _index = record._index;
    
    return *this;
}

DBDNSQuestionRecord &DBDNSQuestionRecord::operator=(const DBDNSQuestionRecord& record)
{
    if (this == &record)
        return *this;
    
    if (record.tag_map)
        tag_map.reset(new std::map<std::string, void *>(*record.tag_map));
    else
        tag_map.reset();
    
    _domain_name = record._domain_name;
    query_type = record.query_type;
    query_class = record.query_class;
    _index = record._index;
    
    return *this;
}

// Public
const std::string &DBDNSQuestionRecord::domain_name() const { return _domain_name; }

std::ostream& operator<<(std::ostream& os, const DBDNSQuestionRecord &question)
{
    os << "<DBDNSQuestionRecord> domain: '" << question.domain_name() << "', type: '" << DNSType_to_string(question.query_type)
    << "', class: '" << DNSClass_to_string(question.query_class) << "', _index: '" << question._index << "' </DBDNSQuestionRecord>";
    return os;
}


/************************** Start of DBDNSResourceRecord *****************************/

// Private

// Constructors
DBDNSResourceRecord::DBDNSResourceRecord(std::string name, uint16_t type, uint16_t cls, uint32_t ttl, uint16_t data_length, const uint8_t *rdata)
: _domain_name(name), query_type(type), query_class(cls), ttl(ttl),
data_length(data_length), data_ptr(new uint8_t [data_length], array_deleter<uint8_t>())
{
    memcpy(data_ptr.get(), rdata, data_length);
}

DBDNSResourceRecord::DBDNSResourceRecord(const DBDNSResourceRecord& record)
: _domain_name(record._domain_name), query_type(record.query_type), query_class(record.query_class), ttl(record.ttl), data_length(record.data_length), data_ptr(record.data_ptr), _index(record._index)
{
    if (record.tag_map)
        tag_map.reset(new std::map<std::string, void *>(*record.tag_map));
}

DBDNSResourceRecord::DBDNSResourceRecord(DBDNSResourceRecord&& record)
: _domain_name(std::move(record._domain_name)), query_type(record.query_type), query_class(record.query_class), ttl(record.ttl), data_length(record.data_length), data_ptr(std::move(record.data_ptr)), tag_map(std::move(record.tag_map)), _index(record._index)
{}

DBDNSResourceRecord &DBDNSResourceRecord::operator=(DBDNSResourceRecord&& record)
{
    if (this == &record)
        return *this;
    
    tag_map = std::move(record.tag_map);
    _domain_name = std::move(record._domain_name);
    query_type = record.query_type;
    query_class = record.query_class;
    ttl = record.ttl;
    data_length = record.data_length;
    data_ptr = std::move(record.data_ptr);
    _index = record._index;
    
    return *this;
}

DBDNSResourceRecord &DBDNSResourceRecord::operator=(const DBDNSResourceRecord& record)
{
    if (this == &record)
        return *this;
    
    if (record.tag_map)
        tag_map.reset(new std::map<std::string, void *>(*record.tag_map));
    else
        tag_map.reset();
    _domain_name = record._domain_name;
    query_type = record.query_type;
    query_class = record.query_class;
    ttl = record.ttl;
    data_length = record.data_length;
    data_ptr = record.data_ptr;
    _index = record._index;
    
    return *this;
}

// Public
uint8_t *DBDNSResourceRecord::data() { return data_ptr.get(); }
const uint8_t *DBDNSResourceRecord::data() const { return data_ptr.get(); }
const std::string &DBDNSResourceRecord::domain_name() const { return _domain_name; }

std::ostream& operator<<(std::ostream& os, const DBDNSResourceRecord &record)
{
    os << "<DBDNSResourceRecord> domain: '" << record.domain_name() << "', type: '" << DNSType_to_string(record.query_type)
    << "', class: '" << DNSClass_to_string(record.query_class) << ", _index: '" << record._index;
    switch (record.query_type) {
        case kDNSType_CNAME:
        case kDNSType_MB:
        case kDNSType_MD:
        case kDNSType_MF:
        case kDNSType_MG:
        case kDNSType_MR:
        case kDNSType_NS:
        case kDNSType_PTR:
            os << "', data: '" << (const char *)record.data() << "', ";
            break;
        
        case kDNSType_A:
            os << "', data: '" << inet_ntoa(*(in_addr *)record.data()) << "', ";
            break;
        
        case kDNSType_AAAA:
            char buf[INET6_ADDRSTRLEN];
            os << "', data: '" << inet_ntop(AF_INET6, record.data(), buf, INET6_ADDRSTRLEN) << "', ";
            break;
            
        default:
            os << "', data: \n++++++++++++++++\n";
            hex_dump_data(record.data_length, record.data(), os);
            os << "++++++++++++++++\n";
            break;
    }
    
    os  << "\t\t</DBDNSResourceRecord>";
    return os;
}



/************************** Start of DBDNSMessage *****************************/

// Private
inline bool DBDNSMessage::populate_questions(DBReadBuffer &data_buf)
{
    for (uint16_t i = 0; i < dns_header.question_count; i++)
    {
        std::string qname = data_buf.read_dns_string();
        uint16_t qtype    = ntohs(data_buf.read_scalar<uint16_t>());
        uint16_t qclass   = ntohs(data_buf.read_scalar<uint16_t>());
        question_records.push_back(DBDNSQuestionRecord(qname, qtype, qclass));
        question_records[i]._index = i;
    }
    
    return true;
}

inline bool DBDNSMessage::populate_records(DBReadBuffer &data_buf, std::vector<DBDNSResourceRecord> &records, uint16_t record_count)
{
    for (uint16_t i = 0; i < record_count; i++)
    {
        std::string qname = data_buf.read_dns_string();
        uint16_t qtype    = ntohs(data_buf.read_scalar<uint16_t>());
        uint16_t qclass   = ntohs(data_buf.read_scalar<uint16_t>());
        uint32_t qttl     = ntohl(data_buf.read_scalar<uint32_t>());
        uint16_t rdlength = ntohs(data_buf.read_scalar<uint16_t>());
        switch (qtype) {
            case kDNSType_CNAME:
            case kDNSType_MB:
            case kDNSType_MD:
            case kDNSType_MF:
            case kDNSType_MG:
            case kDNSType_MR:
            case kDNSType_NS:
            case kDNSType_PTR:
            {
                std::string cname = data_buf.read_dns_string();
                records.push_back(DBDNSResourceRecord(qname, qtype, qclass, qttl, cname.length() + 1, (const uint8_t *)cname.data()));
            }
                break;
                
            case kDNSType_MINFO:
            {
                std::string RMAILBX = data_buf.read_dns_string();
                std::string EMAILBX = data_buf.read_dns_string();
                uint8_t *data = (uint8_t *)malloc(RMAILBX.length() + EMAILBX.length() + 2);
                memcpy(data, RMAILBX.data(), RMAILBX.length() + 1);
                memcpy(data + RMAILBX.length() + 1, EMAILBX.data(), EMAILBX.length() + 1);
                records.push_back(DBDNSResourceRecord(qname, qtype, qclass, qttl, sizeof(data), (const uint8_t *)data));
                free(data);
            }
                break;
                
            case kDNSType_MX:
            {
                uint16_t pref = data_buf.read_scalar<uint16_t>();
                std::string EXCHANGE = data_buf.read_dns_string();
                
                uint8_t *data = (uint8_t *)malloc(sizeof(pref) + EXCHANGE.length() + 1);
                *(uint16_t *)data = pref;
                memcpy(data + sizeof(pref), EXCHANGE.data(), EXCHANGE.length() + 1);
                records.push_back(DBDNSResourceRecord(qname, qtype, qclass, qttl, sizeof(data), (const uint8_t *)data));
                free(data);
            }
                break;
                
            case kDNSType_SOA:
            {
                std::string MNAME = data_buf.read_dns_string();
                std::string RNAME = data_buf.read_dns_string();
                uint32_t SERIAL = data_buf.read_scalar<uint32_t>();
                uint32_t REFRESH = data_buf.read_scalar<uint32_t>();
                uint32_t RETRY = data_buf.read_scalar<uint32_t>();
                uint32_t EXPIRE = data_buf.read_scalar<uint32_t>();
                uint32_t MINIMUM = data_buf.read_scalar<uint32_t>();
                
                uint16_t data_len = MNAME.length() + 1 + RNAME.length() + 1 + sizeof(SERIAL) + sizeof(REFRESH) + sizeof(RETRY) + sizeof(EXPIRE) + sizeof(MINIMUM);
                uint8_t *data = (uint8_t *)malloc(data_len);
                uint8_t *data_it = data;
                
                memcpy(data_it, MNAME.data(), MNAME.length() + 1); data_it += MNAME.length() + 1;
                memcpy(data_it, RNAME.data(), RNAME.length() + 1); data_it += RNAME.length() + 1;
                
                *(uint32_t *)data_it = SERIAL;  data_it += sizeof(SERIAL);
                *(uint32_t *)data_it = REFRESH; data_it += sizeof(REFRESH);
                *(uint32_t *)data_it = RETRY;   data_it += sizeof(RETRY);
                *(uint32_t *)data_it = EXPIRE;  data_it += sizeof(EXPIRE);
                *(uint32_t *)data_it = EXPIRE;  data_it += sizeof(MINIMUM);
                
                records.push_back(DBDNSResourceRecord(qname, qtype, qclass, qttl, data_len, (const uint8_t *)data));
                free(data);
            }
                break;
                
            default:
                records.push_back(DBDNSResourceRecord(qname, qtype, qclass, qttl, rdlength, data_buf.read_ptr_at_current_pos(rdlength)));
                break;
        }
        if (qtype == kDNSType_OPT) {
            if (_is_edns)
                return false;
            _is_edns = true;
            OPT_record = &records[i];
        }
        records[i]._index = i;
    }
    return true;
}

void DBDNSMessage::delete_all_records()
{
    //std::cout << "deleted_questions_idx: ";
    for (auto it = deleted_questions_idx.begin(); it != deleted_questions_idx.end(); ++it) {
        //std::cout << *it << " ";
        question_records.erase(question_records.begin() + *it);
    }
    //std::cout << "\n";
    deleted_questions_idx.clear();
    dns_header.question_count = question_records.size();
    
    //std::cout << "deleted_answers_idx: ";
    for (auto it = deleted_answers_idx.begin(); it != deleted_answers_idx.end(); ++it) {
        //std::cout << *it << " ";
        answer_records.erase(answer_records.begin() + *it);
    }
    //std::cout << "\n";
    deleted_answers_idx.clear();
    dns_header.answer_count = answer_records.size();
    
    //if (!answer_count() && !auth_count())
    //    set_RCODE(kDNSRCODE_Refused);
}

inline void DBDNSMessage::write_records(const std::vector<DBDNSResourceRecord> &records, DBWriteBuffer &output_buffer) const
{
    for (auto& record : records)
    {
        output_buffer.write_dns_string(record.domain_name());
        output_buffer.write_scalar<uint16_t>(htons(record.query_type));
        output_buffer.write_scalar<uint16_t>(htons(record.query_class));
        output_buffer.write_scalar<uint32_t>(htonl(record.ttl));
        
        uint8_t *data_length_addr = output_buffer.write_ptr_at_index(output_buffer.size());
        output_buffer.write_scalar<uint16_t>(htons(record.data_length));
        uint16_t lower_size = output_buffer.size();
        
        switch (record.query_type) {
            case kDNSType_CNAME:
            case kDNSType_MB:
            case kDNSType_MD:
            case kDNSType_MF:
            case kDNSType_MG:
            case kDNSType_MR:
            case kDNSType_NS:
            case kDNSType_PTR:
            {
                std::string cname((const char *)record.data());
                output_buffer.write_dns_string(cname);
            }
                break;
                
            case kDNSType_MINFO:
            {
                std::string RMAILBX((const char *)record.data());
                std::string EMAILBX((const char *)record.data() + RMAILBX.length() + 1);
                output_buffer.write_dns_string(RMAILBX);
                output_buffer.write_dns_string(EMAILBX);
            }
                break;
                
            case kDNSType_MX:
            {
                uint16_t pref = *(uint16_t *)record.data();
                std::string EXCHANGE((const char *)record.data() + sizeof(pref));
                output_buffer.write_scalar<uint16_t>(pref);
                output_buffer.write_dns_string(EXCHANGE);
            }
                break;
                
            case kDNSType_SOA:
            {
                const uint8_t *data_it = record.data();
                
                std::string MNAME((const char *)data_it); data_it += MNAME.length() + 1;
                std::string RNAME((const char *)data_it); data_it += RNAME.length() + 1;
                output_buffer.write_dns_string(MNAME);
                output_buffer.write_dns_string(RNAME);
                
                uint32_t SERIAL = *(uint32_t *)data_it;   data_it += sizeof(SERIAL);
                uint32_t REFRESH = *(uint32_t *)data_it;  data_it += sizeof(REFRESH);
                uint32_t RETRY = *(uint32_t *)data_it;    data_it += sizeof(RETRY);
                uint32_t EXPIRE = *(uint32_t *)data_it;   data_it += sizeof(EXPIRE);
                uint32_t MINIMUM = *(uint32_t *)data_it;  data_it += sizeof(MINIMUM);
                output_buffer.write_scalar<uint32_t>(SERIAL);
                output_buffer.write_scalar<uint32_t>(REFRESH);
                output_buffer.write_scalar<uint32_t>(RETRY);
                output_buffer.write_scalar<uint32_t>(EXPIRE);
                output_buffer.write_scalar<uint32_t>(MINIMUM);
            }
                break;
                
            default:
                memcpy(output_buffer.write_ptr_at_current_pos(record.data_length), record.data(), record.data_length);
                break;
        }
        
        uint16_t data_length = htons(output_buffer.size() - lower_size);
        memcpy(data_length_addr, &data_length, sizeof(data_length));
    }
}

void DBDNSMessage::create_output() const
{
    DBWriteBuffer output_buffer(output_cache_size);
    
    // Write TCP Size Guard ;)
    output_buffer.write_scalar<uint16_t>(0);
    
    // Write the header
    output_buffer.write_scalar<uint16_t>(htons(dns_header.identification));
    output_buffer.write_scalar<uint16_t>(htons(dns_header.control));
    output_buffer.write_scalar<uint16_t>(htons(dns_header.question_count));
    output_buffer.write_scalar<uint16_t>(htons(dns_header.answer_count));
    output_buffer.write_scalar<uint16_t>(htons(dns_header.authority_count));
    output_buffer.write_scalar<uint16_t>(htons(dns_header.additional_count));
    
    // Write the questions
    for (auto& question : question_records)
    {
        output_buffer.write_dns_string(question.domain_name());
        output_buffer.write_scalar<uint16_t>(htons(question.query_type));
        output_buffer.write_scalar<uint16_t>(htons(question.query_class));
    }
    
    // Write the records
    write_records(answer_records, output_buffer);
    write_records(auth_records, output_buffer);
    write_records(additional_records, output_buffer);
    
    //output_buffer.print_comp_state();
    
    // Transfer ownership of data
    output_data_size = output_buffer.size();
    output_data_ptr = output_buffer.take_ownership();
    
    // TCP Guard
    *((uint16_t *)output_data_ptr.get()) = htons((uint16_t)output_data_size - 2);
}

// Constructors
DBDNSMessage::DBDNSMessage(std::shared_ptr<const uint8_t> data, size_t data_length, DNSMessageType type)
{
    if (data_length == 0)
        return;
    
    DBReadBuffer data_buf(data, data_length);
    
    dns_header = {
        ntohs(data_buf.read_scalar<uint16_t>()), // identification
        ntohs(data_buf.read_scalar<uint16_t>()), // control
        ntohs(data_buf.read_scalar<uint16_t>()), // question_count
        ntohs(data_buf.read_scalar<uint16_t>()), // answer_count
        ntohs(data_buf.read_scalar<uint16_t>()), // authority_count
        ntohs(data_buf.read_scalar<uint16_t>())  // additional_count
    };
    
    //if ((dns_header.control & 0x000F) != kDNSRCODE_NoError)
    //    return;
    
    if (message_type() != type)
        return;
    
    if (!populate_questions(data_buf))
        return;
    
    if (!populate_records(data_buf, answer_records, dns_header.answer_count))
        return;
    if (_is_edns)
        return;
    
    if (!populate_records(data_buf, auth_records, dns_header.authority_count))
        return;
    if (_is_edns)
        return;
    
    if (!populate_records(data_buf, additional_records, dns_header.additional_count))
        return;
    if (_is_edns)
        if ((OPT_record->ttl & 0x00FF0000) != EDNS_VERSION_0)
            return;
    
    _is_good = true;
    
    if (debug_dns_message)
    {
        if (type == DNSResponseType)
            std::cout << "\n\nRESPONSE:\n";
        else
            std::cout << "\n\nQUERY:\n";
        hex_dump_data(data_length, data.get(), std::cout, 16);
        std::cout << *this << "\n\n";
    }
}

DBDNSMessage::DBDNSMessage(const DBDNSMessage &message)
: dns_header(message.dns_header),
_is_good(message._is_good), _is_edns(message._is_edns),

question_records(message.question_records), answer_records(message.answer_records),
auth_records(message.auth_records), additional_records(message.additional_records),

deleted_questions_idx(message.deleted_questions_idx),
deleted_answers_idx(message.deleted_answers_idx),

output_data_size(message.output_data_size),

OPT_record(message.OPT_record ? &additional_records[message.OPT_record->_index] : nullptr)
{
    if (message.tag_map)
        tag_map.reset(new std::map<std::string, void *>(*message.tag_map));
    
    if (message.output_data_ptr)
    {
        output_data_ptr.reset(new uint8_t[message.output_data_size]);
        memcpy(output_data_ptr.get(), message.output_data_ptr.get(), message.output_data_size);
    }
}

DBDNSMessage::DBDNSMessage(DBDNSMessage &&message)
: dns_header(message.dns_header),
_is_good(message._is_good), _is_edns(message._is_edns),

question_records(std::move(message.question_records)),
answer_records(std::move(message.answer_records)),
auth_records(std::move(message.auth_records)),
additional_records(std::move(message.additional_records)),

deleted_questions_idx(std::move(message.deleted_questions_idx)),
deleted_answers_idx(std::move(message.deleted_answers_idx)),

OPT_record(message.OPT_record ? &additional_records[message.OPT_record->_index] : nullptr),
output_data_ptr(std::move(message.output_data_ptr)),

tag_map(std::move(message.tag_map))
{
    message.OPT_record = nullptr;
}

DBDNSMessage &DBDNSMessage::operator=(const DBDNSMessage &message)
{
    if (this == &message)
        return *this;
    
    question_records = message.question_records;
    answer_records = message.answer_records;
    auth_records = message.auth_records;
    additional_records = message.additional_records;
    
    deleted_questions_idx = message.deleted_questions_idx;
    deleted_answers_idx = message.deleted_answers_idx;
    
    _is_good = message._is_good;
    _is_edns = message._is_edns;
    OPT_record = message.OPT_record ? &additional_records[message.OPT_record->_index] : nullptr;
    
    dns_header = message.dns_header;
    
    if (message.output_data_ptr)
    {
        output_data_ptr.reset(new uint8_t[message.output_data_size]);
        memcpy(output_data_ptr.get(), message.output_data_ptr.get(), message.output_data_size);
    }
    else
        output_data_ptr.reset();
    
    if (message.tag_map)
        tag_map.reset(new std::map<std::string, void *>(*message.tag_map));
    else
        tag_map.reset();
    
    return *this;
}

DBDNSMessage &DBDNSMessage::operator=(DBDNSMessage &&message)
{
    if (this == &message)
        return *this;
    
    question_records = std::move(message.question_records);
    answer_records = std::move(message.answer_records);
    auth_records = std::move(message.auth_records);
    additional_records = std::move(message.additional_records);
    
    deleted_questions_idx = std::move(message.deleted_questions_idx);
    deleted_answers_idx = std::move(message.deleted_answers_idx);
    
    _is_good = message._is_good; message._is_good = false;
    _is_edns = message._is_edns; message._is_edns = false;
    OPT_record = message.OPT_record ? &additional_records[message.OPT_record->_index] : nullptr;
    message.OPT_record = nullptr;
    
    dns_header = message.dns_header;
    message.dns_header = {0};
    
    output_data_ptr = std::move(message.output_data_ptr);
    
    tag_map = std::move(message.tag_map);
    
    return *this;
}

// Public
DBDNSMessage::DNSMessageType DBDNSMessage::message_type() const { return (dns_header.control & 0x8000) ? DNSResponseType : DNSQueryType; }
uint16_t DBDNSMessage::identification() const { return dns_header.identification; }

bool DBDNSMessage::is_good() const { return _is_good; }

std::vector<DBDNSQuestionRecord> &DBDNSMessage::questions()   { return question_records; }
std::vector<DBDNSResourceRecord> &DBDNSMessage::answers()     { return answer_records; }
std::vector<DBDNSResourceRecord> &DBDNSMessage::authorities() { return auth_records; }
std::vector<DBDNSResourceRecord> &DBDNSMessage::additionals() { return additional_records; }

const std::vector<DBDNSQuestionRecord> &DBDNSMessage::questions()   const { return question_records; }
const std::vector<DBDNSResourceRecord> &DBDNSMessage::answers()     const { return answer_records; }
const std::vector<DBDNSResourceRecord> &DBDNSMessage::authorities() const { return auth_records; }
const std::vector<DBDNSResourceRecord> &DBDNSMessage::additionals() const { return additional_records; }

void DBDNSMessage::delete_record(const DBDNSResourceRecord &record) { deleted_answers_idx.insert(record._index); }
void DBDNSMessage::delete_record(const DBDNSQuestionRecord &record) { deleted_questions_idx.insert(record._index); }

unsigned short DBDNSMessage::question_count()   const { return question_records.size(); }
unsigned short DBDNSMessage::answer_count()     const { return answer_records.size(); }
unsigned short DBDNSMessage::auth_count()       const { return auth_records.size(); }
unsigned short DBDNSMessage::additional_count() const { return additional_records.size(); }

const uint8_t *DBDNSMessage::bytes(bool tcp_guard) const
{
    if (!output_data_ptr)
        create_output();
    
    //std::cout << *this;
    
    /*if (debug_dns_message)
    {
        if (message_type() == DNSResponseType)
            std::cout << "\n\nRESPONSE:\n";
        else
            std::cout << "\n\nQUERY:\n";
        
        hex_dump(std::cout, 16);
    }*/
    
    return output_data_ptr.get() + (tcp_guard ? 0 : 2);
}

size_t DBDNSMessage::bytes_length(bool tcp_guard) const
{
    if (!output_data_ptr)
        create_output();
    
    return output_data_size - (tcp_guard ? 0 : 2);
}

void DBDNSMessage::set_type(bool type)
{
    if (type == DNSResponseType) {
        dns_header.control |= 0x8000;  // Set Response
        if (_is_edns)
            OPT_record->query_class = 4096; // Set the OPT Payload size
    } else
        dns_header.control &= ~0x8000; // Set Query
}

void DBDNSMessage::set_RCODE(uint16_t code)
{
    dns_header.control = (dns_header.control & 0xFFF0) | (code & 0x0F);
    
    // Set the rest of the EDNS RCODE bits
    if (_is_edns)
        OPT_record->ttl = (OPT_record->ttl & 0x00FFFFFF) | ((uint32_t)(code & 0x0FF0) << 20);
}

void DBDNSMessage::hex_dump(std::ostream &o, int char_per_line, bool tcp_guard) const
{
    if (!output_data_ptr)
        create_output();
    
    o << "DBDNSMessage: ";
    hex_dump_data(bytes_length(tcp_guard), bytes(tcp_guard), o, char_per_line);
}

std::ostream& operator<<(std::ostream& os, const DBDNSMessage &message)
{
    os << "<DBDNSMessage>\n\t_is_good: " << std::boolalpha << message._is_good << ", _is_edns: " << message._is_edns << std::noboolalpha << "\n"
    << "\tID: 0x" << std::hex << message.dns_header.identification << ", control: 0x" << message.dns_header.control << std::dec << "\n"
    << "\tQuestionsCnt: " << message.question_count() << ", AnswersCnt: " << message.answer_count() << "\n"
    << "\tAuthoritiesCnt: " << message.auth_count() << ", AdditionalsCnt: " << message.additional_count() << "\n";
    
    os << "\tQuestion Records:\n";
    for (auto &q : message.questions())
        os << "\t\t" << q << "\n";
    
    os << "\tAnswer Records:\n";
    for (auto &q : message.answers())
        os << "\t\t" << q << "\n";
    
    os << "\tAuthority Records:\n";
    for (auto &q : message.authorities())
        os << "\t\t" << q << "\n";
    
    os << "\tAdditional Records:\n";
    for (auto &q : message.additionals())
        os << "\t\t" << q << "\n";
    
    os << "</DBDNSMessage>\n";
    return os;
}

