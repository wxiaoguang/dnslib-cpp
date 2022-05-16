/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sstream>
#include <cstring>
#include <iomanip>

#include "buffer.h"
#include "rr.h"

namespace dns {

std::ostringstream RData::ossDebugString() {
    std::ostringstream oss;
    if (record) {
        oss << toString(getType()) << " " << (record->mDomainName.empty() ? "." : record->mDomainName) << " " << toString(record->mClass) << " " << record->mTtl;
    } else {
        oss << toString(getType()) << " . None 0";
    }
    return oss;
}

/////////// RDataWithName ///////////

void RDataWithName::decode(Buffer &buffer, size_t /*dataSize*/) {
    mName = buffer.readDomainName();
}

void RDataWithName::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
}

std::string RDataWithName::toDebugString() {
    auto oss = ossDebugString();
    oss << " name=" << mName;
    return oss.str();
}


/////////// RDataHINFO /////////////////

void RDataHINFO::decode(Buffer &buffer, size_t /*dataSize*/) {
    mCpu = buffer.readCharString();
    mOs = buffer.readCharString();
}

void RDataHINFO::encode(Buffer &buffer) {
    buffer.writeCharString(mCpu);
    buffer.writeCharString(mOs);
}

std::string RDataHINFO::toDebugString() {
    auto oss = ossDebugString();
    oss << " cpu=" << mCpu << " os=" << mOs;
    return oss.str();
}


/////////// RDataMINFO /////////////////

void RDataMINFO::decode(Buffer &buffer, size_t /*dataSize*/) {
    mRMailBx = buffer.readDomainName();
    mMailBx = buffer.readDomainName();
}

void RDataMINFO::encode(Buffer &buffer) {
    buffer.writeDomainName(mRMailBx);
    buffer.writeDomainName(mMailBx);
}

std::string RDataMINFO::toDebugString() {
    auto oss = ossDebugString();
    oss << " rmailbx=" << mRMailBx << " mailbx=" << mMailBx;
    return oss.str();
}


/////////// RDataMX /////////////////
void RDataMX::decode(Buffer &buffer, size_t /*dataSize*/) {
    mPreference = buffer.readUint16();
    mExchange = buffer.readDomainName();
}

void RDataMX::encode(Buffer &buffer) {
    buffer.writeUint16(mPreference);
    buffer.writeDomainName(mExchange);
}

std::string RDataMX::toDebugString() {
    auto oss = ossDebugString();
    oss << " preference=" << mPreference << " exchange=" << mExchange;
    return oss.str();
}

/////////// RDataUnknown /////////////////

void RDataUnknown::decode(Buffer &buffer, size_t dataSize) {
    auto *data = buffer.readBytes(dataSize);
    if (!data) return;
    mData.assign(data, data + dataSize);
}

void RDataUnknown::encode(Buffer &buffer) {
    buffer.writeBytes(mData.data(), mData.size());
}

std::string RDataUnknown::toDebugString() {
    auto oss = ossDebugString();
    oss << " len=" << mData.size();
    return oss.str();
}

/////////// RDataSOA /////////////////

void RDataSOA::decode(Buffer &buffer, size_t /*dataSize*/) {
    mMName = buffer.readDomainName();
    mRName = buffer.readDomainName();
    mSerial = buffer.readUint32();
    mRefresh = buffer.readUint32();
    mRetry = buffer.readUint32();
    mExpire = buffer.readUint32();
    mMinimum = buffer.readUint32();
}

void RDataSOA::encode(Buffer &buffer) {
    buffer.writeDomainName(mMName);
    buffer.writeDomainName(mRName);
    buffer.writeUint32(mSerial);
    buffer.writeUint32(mRefresh);
    buffer.writeUint32(mRetry);
    buffer.writeUint32(mExpire);
    buffer.writeUint32(mMinimum);
}

std::string RDataSOA::toDebugString() {
    auto oss = ossDebugString();
    oss << " mname=" << mMName
        << " rname=" << mRName
        << " serial=" << mSerial
        << " refresh=" << mRefresh
        << " retry=" << mRetry
        << " expire=" << mExpire
        << " minimum=" << mMinimum;
    return oss.str();
}


/////////// RDataTXT /////////////////

void RDataTXT::decode(Buffer &buffer, size_t dataSize) {
    mTexts.clear();
    size_t posStart = buffer.pos();
    while (!buffer.isBroken() && buffer.pos() - posStart < dataSize) {
        mTexts.push_back(buffer.readCharString());
    }
}

void RDataTXT::encode(Buffer &buffer) {
    for (auto it = mTexts.begin(); it != mTexts.end(); ++it) {
        buffer.writeCharString(*it);
    }
}

std::string RDataTXT::toDebugString() {
    auto oss = ossDebugString();
    for (auto &txt : mTexts) {
        oss << " txt=\"" << txt << "\""; // FIXME: escape
    }
    return oss.str();
}

/////////// RDataA /////////////////

void RDataA::decode(Buffer &buffer, size_t /*dataSize*/) {
    // get data from buffer
    auto *data = buffer.readBytes(4);
    if (!data) return;
    memcpy(mAddr, data, 4);
}

void RDataA::encode(Buffer &buffer) {
    for (auto i = 0; i < 4; i++) {
        buffer.writeUint8(mAddr[i]);
    }
}

std::string RDataA::toDebugString() {
    auto oss = ossDebugString();
    oss << " addr=" << (uint32_t)mAddr[0] << '.' << (uint32_t)mAddr[1] << '.' << (uint32_t)mAddr[2] << '.' << (uint32_t)mAddr[3];
    return oss.str();
}

/////////// RDataWKS /////////////////

void RDataWKS::decode(Buffer &buffer, size_t dataSize) {
    // get ip address
    auto *data = buffer.readBytes(4);
    if (!data) return;

    memcpy(mAddr, data, 4);

    // get protocol
    mProtocol = buffer.readUint8();

    // get bitmap
    auto mBitmapSize = dataSize - 5;
    data = buffer.readBytes(mBitmapSize);
    if (!data) return;

    mBitmap.resize(mBitmapSize);
    std::memcpy(mBitmap.data(), data, mBitmapSize);
}

void RDataWKS::encode(Buffer &buffer) {
    // put ip address
    for (auto i = 0; i < 4; i++) {
        buffer.writeUint8(mAddr[i]);
    }

    // put protocol
    buffer.writeUint8(mProtocol);

    // put bitmap
    if (!mBitmap.empty())
        buffer.writeBytes(mBitmap.data(), mBitmap.size());
}

std::string RDataWKS::toDebugString() {
    auto oss = ossDebugString();
    oss << " addr="
        << (uint32_t) mAddr[0] << '.' << (uint32_t) mAddr[1] << '.' << (uint32_t) mAddr[2] << '.' << (uint32_t) mAddr[3]
        << " protocol=" << (uint32_t) mProtocol << " bitmap-size=" << mBitmap.size();
    return oss.str();
}


/////////// RDataAAAA /////////////////

void RDataAAAA::decode(Buffer &buffer, size_t /*dataSize*/) {
    // get data from buffer
    auto *data = buffer.readBytes(16);
    if (!data) return;

    memcpy(mAddr, data, 16);
}

void RDataAAAA::encode(Buffer &buffer) {
    for (auto i = 0; i < 16; i++) {
        buffer.writeUint8(mAddr[i]);
    }
}

std::string RDataAAAA::toDebugString() {
    auto oss = ossDebugString();
    oss << " addr=";
    char hexbuf[3];
    for (auto i = 0; i < 16; i += 2) {
        if (i > 0) {
            oss << ':';
        }
        sprintf(hexbuf, "%02x", mAddr[i]);
        oss << hexbuf;
        sprintf(hexbuf, "%02x", mAddr[i+1]);
        oss << hexbuf;
    }
    return oss.str();
}


/////////// RDataNAPTR /////////////////

void RDataNAPTR::decode(Buffer &buffer, size_t /*dataSize*/) {
    mOrder = buffer.readUint16();
    mPreference = buffer.readUint16();
    mFlags = buffer.readCharString();
    mServices = buffer.readCharString();
    mRegExp = buffer.readCharString();
    mReplacement = buffer.readDomainName(false);
}

void RDataNAPTR::encode(Buffer &buffer) {
    buffer.writeUint16(mOrder);
    buffer.writeUint16(mPreference);
    buffer.writeCharString(mFlags);
    buffer.writeCharString(mServices);
    buffer.writeCharString(mRegExp);
    buffer.writeDomainName(mReplacement, false);
}

std::string RDataNAPTR::toDebugString() {
    auto oss = ossDebugString();
    oss << "type=NAPTR, order=" << mOrder << " preference=" << mPreference << " flags=" << mFlags << " services=" << mServices << " regexp=" << mRegExp << " replacement=" << mReplacement;
    return oss.str();
}

/////////// RDataSRV /////////////////
void RDataSRV::decode(Buffer &buffer, size_t dataSize) {
    mPriority = buffer.readUint16();
    mWeight = buffer.readUint16();
    mPort = buffer.readUint16();

    size_t posStart = buffer.pos();
    while (!buffer.isBroken() && buffer.pos() - posStart < dataSize - 6) {
        mTarget.append(buffer.readCharString());
        mTarget.append(".");
    }
    if (!mTarget.empty()) mTarget.pop_back();
    if (!mTarget.empty()) mTarget.pop_back();
}

void RDataSRV::encode(Buffer &buffer) {
    buffer.writeUint16(mPriority);
    buffer.writeUint16(mWeight);
    buffer.writeUint16(mPort);
    buffer.writeCharString(mTarget);
}

std::string RDataSRV::toDebugString() {
    auto oss = ossDebugString();
    oss << "type=SRV, priority=" << mPriority << " weight=" << mWeight << " port=" << mPort << " target=" << mTarget;
    return oss.str();
}

/*
RDataOPT
+------------+--------------+------------------------------+
| Field Name | Field Type   | Description                  |
+------------+--------------+------------------------------+
| NAME       | domain name  | MUST be 0 (root domain)      |
| TYPE       | u_int16_t    | OPT (41)                     |
| CLASS      | u_int16_t    | requestor's UDP payload size |
| TTL        | u_int32_t    | extended RCODE and flags     |
| RDLEN      | u_int16_t    | length of all RDATA          |
| RDATA      | octet stream | {attribute,value} pairs      |
+------------+--------------+------------------------------+
OPT TTL
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
0: |         EXTENDED-RCODE        |            VERSION            |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
2: | DO|                           Z                               |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */
void RDataOPT::decode(Buffer &buffer, size_t /*dataSize*/) {
    auto dataLen = buffer.readUint16();
    auto bytes = buffer.readBytes(dataLen);
    if (bytes) {
        mData.resize(dataLen);
        memcpy(mData.data(), bytes, dataLen);
    }
}

void RDataOPT::encode(Buffer &buffer) {
    buffer.writeUint16(mData.size());
    buffer.writeBytes(mData.data(), mData.size());
}

std::string RDataOPT::toDebugString() {
    auto oss = std::ostringstream();
    oss << "OPT payload_size=" << (uint16_t)record->mClass << " ext=" << (uint32_t) record->mTtl << " len=" << mData.size();
    return oss.str();
}

/////////// ResourceRecord ////////////

void ResourceRecord::decode(Buffer &buffer) {
    mDomainName = buffer.readDomainName();
    mType = (RecordDataType)buffer.readUint16();

    // some data type (like OPT) will use Class/Ttl as other meanings
    mClass = (RecordClass) buffer.readUint16();
    mTtl = buffer.readUint32();

    auto rDataSize = buffer.readUint16();
    switch (mType) {
        case RecordDataType::RDATA_CNAME:
            mRData = std::make_shared<RDataCNAME>();
            break;
        case RecordDataType::RDATA_HINFO:
            mRData = std::make_shared<RDataHINFO>();
            break;
        case RecordDataType::RDATA_MB:
            mRData = std::make_shared<RDataMB>();
            break;
        case RecordDataType::RDATA_MD:
            mRData = std::make_shared<RDataMD>();
            break;
        case RecordDataType::RDATA_MF:
            mRData = std::make_shared<RDataMF>();
            break;
        case RecordDataType::RDATA_MG:
            mRData = std::make_shared<RDataMG>();
            break;
        case RecordDataType::RDATA_MINFO:
            mRData = std::make_shared<RDataMINFO>();
            break;
        case RecordDataType::RDATA_MR:
            mRData = std::make_shared<RDataMR>();
            break;
        case RecordDataType::RDATA_MX:
            mRData = std::make_shared<RDataMX>();
            break;
        case RecordDataType::RDATA_NS:
            mRData = std::make_shared<RDataNS>();
            break;
        case RecordDataType::RDATA_PTR:
            mRData = std::make_shared<RDataPTR>();
            break;
        case RecordDataType::RDATA_SOA:
            mRData = std::make_shared<RDataSOA>();
            break;
        case RecordDataType::RDATA_TXT:
            mRData = std::make_shared<RDataTXT>();
            break;
        case RecordDataType::RDATA_A:
            mRData = std::make_shared<RDataA>();
            break;
        case RecordDataType::RDATA_WKS:
            mRData = std::make_shared<RDataWKS>();
            break;
        case RecordDataType::RDATA_AAAA:
            mRData = std::make_shared<RDataAAAA>();
            break;
        case RecordDataType::RDATA_NAPTR:
            mRData = std::make_shared<RDataNAPTR>();
            break;
        case RecordDataType::RDATA_SRV:
            mRData = std::make_shared<RDataSRV>();
            break;
        case RecordDataType::RDATA_OPT:
            mRData = std::make_shared<RDataOPT>();
            break;
        default:
            mRData = std::make_shared<RDataUnknown>();
    }

    mRData->record = this;

    // RData can refer to the offset after the rDataSize in buffer
    if (rDataSize) {
        auto expectedEndPos = buffer.pos() + rDataSize;
        mRData->decode(buffer, rDataSize);
        if (buffer.pos() != expectedEndPos) {
            buffer.markBroken(BufferResult::InvalidData);
        }
    }
}

void ResourceRecord::encode(Buffer &buffer) {
    buffer.writeDomainName(mDomainName);
    buffer.writeUint16((uint16_t)mRData->getType());
    // TODO: some data type (like OPT) will use Class/Ttl as other meanings
    buffer.writeUint16((uint16_t)mClass);
    buffer.writeUint32(mTtl);
    // save position of buffer for later use (write length of RData part)
    size_t bufferPosRDataLength = buffer.pos();
    buffer.writeUint16(0); // this value could be later overwritten
    // encode RData if present
    if (mRData) {
        mRData->encode(buffer);
        // sub 2 because two bytes for RData length are not part of RData block
        auto rDataSize = buffer.pos() - bufferPosRDataLength - 2;
        size_t bufferLastPos = buffer.pos();
        buffer.seek(bufferPosRDataLength);
        buffer.writeUint16(rDataSize); // overwrite 0 with actual size of RData
        buffer.seek(bufferLastPos);
    }
}

std::string ResourceRecord::toDebugString() {
    return mRData->toDebugString();
}

std::string toString(RecordClass c) {
    switch (c) {
        case RecordClass::CLASS_None:
            return "None";
        case RecordClass::CLASS_IN:
            return "IN";
        case RecordClass::CLASS_CS:
            return "CS";
        case RecordClass::CLASS_CH:
            return "CH";
        case RecordClass::CLASS_HS:
            return "HS";
        default:
            return "Class(" + std::to_string((int)c) + ")";
    }
}

std::string toString(RecordDataType t) {
    switch (t) {
        case RecordDataType::RDATA_None:
            return "None";
        case RecordDataType::RDATA_CNAME:
            return "CNAME";
        case RecordDataType::RDATA_HINFO:
            return "HINFO";
        case RecordDataType::RDATA_MB:
            return "MB";
        case RecordDataType::RDATA_MD:
            return "MD";
        case RecordDataType::RDATA_MF:
            return "MF";
        case RecordDataType::RDATA_MG:
            return "MG";
        case RecordDataType::RDATA_MINFO:
            return "MINFO";
        case RecordDataType::RDATA_MR:
            return "MR";
        case RecordDataType::RDATA_MX:
            return "MX";
        case RecordDataType::RDATA_NS:
            return "NS";
        case RecordDataType::RDATA_PTR:
            return "PTR";
        case RecordDataType::RDATA_SOA:
            return "SOA";
        case RecordDataType::RDATA_TXT:
            return "TXT";
        case RecordDataType::RDATA_A:
            return "A";
        case RecordDataType::RDATA_WKS:
            return "WKS";
        case RecordDataType::RDATA_AAAA:
            return "AAAA";
        case RecordDataType::RDATA_NAPTR:
            return "NAPTR";
        case RecordDataType::RDATA_SRV:
            return "SRV";
        case RecordDataType::RDATA_OPT:
            return "OPT";
        default:
            return "Type(" + std::to_string((int)t) + ")";
    }
}

}