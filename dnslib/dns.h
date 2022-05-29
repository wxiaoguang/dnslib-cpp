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

// RCode types, use uint16_t to match the type of Message::mRCode
enum class ResponseCode : uint16_t {
    NOERROR = 0,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
    // 6-15 reserved for future use
};

// Record CLASS
enum class RecordClass : uint16_t {
    None = 0,
    IN, // the Internet
    CS, // the CSNET class (Obsolete)
    CH, // the CHAOS class
    HS, // Hesiod
};

// Record TYPE (aka RData types)
enum class RecordType : uint16_t {
    None = 0,

    A = 1, // IPv4 address
    NS = 2, // authoritative name server

    MD = 3, // mail destination (Obsolete - use MX)
    MF = 4, // mail forwarder (Obsolete - use MX)

    CNAME = 5, // canonical name for an alias
    SOA = 6, // marks the start of a zone of authority

    MB = 7, // mailbox domain name (Obsolete)
    MG = 8, // mail group member (Obsolete)
    MR = 9, // mail rename domain name (Obsolete)
    NUL = 10, // null record (Obsolete)
    WKS = 11, // well known service description (Obsolete)

    PTR = 12, // domain name pointer
    HINFO = 13, // host information

    MINFO = 14, // mailbox or mail list information (Obsolete)

    MX = 15, // mail exchange
    TXT = 16, // text strings
    AAAA = 28, // IPv6 address
    SRV = 33, // service record specifies
    NAPTR = 35, // naming authority pointer

    OPT = 41, // pseudo-record to support EDNS
    ANY = 255, // wildcard *
};

std::string toString(RecordClass c);
std::string toString(RecordType t);

} // namespace
#endif	/* _DNS_DNS_H */
