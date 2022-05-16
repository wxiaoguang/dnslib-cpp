/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#ifndef _DNS_DNS_H
#define	_DNS_DNS_H

#include <cstdint>

namespace dns {

// maximal length of domain label name
const size_t MAX_MSG_LEN = 512;
const size_t MAX_LABEL_LEN = 63;
const size_t MAX_DOMAIN_LEN = 255;

// CLASS types
enum class RecordClass : uint16_t {
    CLASS_None = 0,
    CLASS_IN,     // the Internet
    CLASS_CS,     // the CSNET class (Obsolete)
    CLASS_CH,     // the CHAOS class
    CLASS_HS,     // Hesiod
};

// RData types
enum class RecordDataType : uint16_t {
    RDATA_None = 0,
    // a host address
    RDATA_A = 1,
    // an authoritative name server
    RDATA_NS = 2,
    // a mail destination (Obsolete - use MX)
    RDATA_MD = 3,
    // a mail forwarder (Obsolete - use MX)
    RDATA_MF = 4,
    // the canonical name for an alias
    RDATA_CNAME = 5,
    // marks the start of a zone of authority
    RDATA_SOA = 6,
    // a mailbox domain name (EXPERIMENTAL)
    RDATA_MB = 7,
    // a mail group member (EXPERIMENTAL)
    RDATA_MG = 8,
    // a mail rename domain name (EXPERIMENTAL)
    RDATA_MR = 9,
    // a null RR (EXPERIMENTAL)
    RDATA_NULL = 10,
    // a well known service description
    RDATA_WKS = 11,
    // a domain name pointer
    RDATA_PTR = 12,
    // host information
    RDATA_HINFO = 13,
    // mailbox or mail list information
    RDATA_MINFO = 14,
    // mail exchange
    RDATA_MX = 15,
    // text strings
    RDATA_TXT = 16,
    // IPv6 address
    RDATA_AAAA = 28,
    // service record specifies
    RDATA_SRV = 33,
    // naming authority pointer
    RDATA_NAPTR = 35,

    RDATA_OPT = 41,
};

std::string toString(RecordClass c);
std::string toString(RecordDataType t);

} // namespace
#endif	/* _DNS_DNS_H */
