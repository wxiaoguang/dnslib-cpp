/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#ifndef _DNS_BUFFER_H
#define	_DNS_BUFFER_H

#include <string>
#include <vector>

#include "dns.h"

namespace dns
{
enum class BrokenReason {
    None,
    BufferOverflow,
    InvalidData,
    LabelCompressionLoop,
    LabelCompressionDisallowed,
    LabelTooLong,
    DomainTooLong,
};
/**
 * Buffer for DNS protocol parsing and serialization
 *
 * <domain-name> is a domain name represented as a series of labels, and
 * terminated by a label with zero length.
 *
 * <character-string> is a single length octet followed by that number
 * of characters.  <character-string> is treated as binary information,
 * and can be up to 256 characters in length (including the length octet).
 *
 */
class Buffer {
public:
    Buffer() = delete;
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    Buffer(uint8_t *buffer, size_t bufferSize) : bufBase(buffer), bufPtr(buffer), bufLen(bufferSize) {}

    // for debug purpose only
    Buffer(const char *buffer, size_t bufferSize) : Buffer((uint8_t *) buffer, bufferSize) {}

    inline size_t pos() const { return bufPtr - bufBase; }
    inline uint8_t *ptr() { return bufPtr; }
    inline size_t size() const { return bufLen; }
    void seek(size_t pos);

    uint8_t readUint8();
    void writeUint8(uint8_t value);

    uint16_t readUint16();
    void writeUint16(uint16_t value);

    uint32_t readUint32();
    void writeUint32(uint32_t value);

    uint8_t *readBytes(size_t count);
    void writeBytes(const uint8_t *data, size_t count);

    // read & write <character-string> (according to RFC 1035) from buffer
    std::string readCharString();
    void writeCharString(const std::string &value);

    // read & write <domain> (according to RFC 1035) from buffer
    std::string readDomainName(bool compressionAllowed = true);
    void writeDomainName(const std::string &value, bool compressionAllowed = true);

    inline BrokenReason brokenReason() { return broken; }
    inline bool isBroken() { return broken != BrokenReason::None; }
    inline void markBroken(BrokenReason b) { broken = b; }

private:
    uint8_t *movePtr(uint8_t *newPtr); // returns the old pos ptr. returns nullptr if buffer is broken

    BrokenReason broken{};

    uint8_t *bufBase;
    uint8_t *bufPtr;
    const size_t bufLen;

    std::vector<size_t> linkPos; // list of link positions visited when decoding domain name
};

} // namespace
#endif	/* _DNS_BUFFER_H */
