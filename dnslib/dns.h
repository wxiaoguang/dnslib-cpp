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
enum class RecordType : uint16_t {
    RDATA_None = 0,

    RDATA_A = 1, // IPv4 address
    RDATA_NS = 2, // authoritative name server

    RDATA_MD = 3, // mail destination (Obsolete - use MX)
    RDATA_MF = 4, // mail forwarder (Obsolete - use MX)

    RDATA_CNAME = 5, // canonical name for an alias
    RDATA_SOA = 6, // marks the start of a zone of authority

    RDATA_MB = 7, // mailbox domain name (Obsolete)
    RDATA_MG = 8, // mail group member (Obsolete)
    RDATA_MR = 9, // mail rename domain name (Obsolete)
    RDATA_NULL = 10, // null record (Obsolete)
    RDATA_WKS = 11, // well known service description (Obsolete)

    RDATA_PTR = 12, // domain name pointer
    RDATA_HINFO = 13, // host information

    RDATA_MINFO = 14, // mailbox or mail list information (Obsolete)

    RDATA_MX = 15, // mail exchange
    RDATA_TXT = 16, // text strings
    RDATA_AAAA = 28, // IPv6 address
    RDATA_SRV = 33, // service record specifies
    RDATA_NAPTR = 35, // naming authority pointer

    RDATA_OPT = 41, // pseudo-record to support EDNS
    RDATA_ANY = 255,
};

std::string toString(RecordClass c);
std::string toString(RecordType t);

} // namespace
#endif	/* _DNS_DNS_H */
