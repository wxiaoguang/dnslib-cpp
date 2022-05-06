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

using namespace dns;

/////////// RDataWithName ///////////

void RDataWithName::decode(Buffer &buffer, size_t /*dataSize*/) {
    mName = buffer.readDomainName();
}

void RDataWithName::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
}

/////////// RDataCNAME /////////////////

std::string RDataCNAME::asString() {
    std::ostringstream text;
    text << "<<CNAME domainName=" << mName;
    return text.str();
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

std::string RDataHINFO::asString() {
    std::ostringstream text;
    text << "<<HINFO cpu=" << mCpu << " os=" << mOs;
    return text.str();
}

/////////// RDataMB /////////////////

std::string RDataMB::asString() {
    std::ostringstream text;
    text << "<<MB madname=" << mName;
    return text.str();
}

/////////// RDataMD /////////////////

std::string RDataMD::asString() {
    std::ostringstream text;
    text << "<<MD madname=" << mName;
    return text.str();
}

/////////// RDataMF /////////////////

std::string RDataMF::asString() {
    std::ostringstream text;
    text << "<<MF madname=" << mName;
    return text.str();
}

/////////// RDataMG /////////////////

std::string RDataMG::asString() {
    std::ostringstream text;
    text << "<<MG madname=" << mName;
    return text.str();
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

std::string RDataMINFO::asString() {
    std::ostringstream text;
    text << "<<MINFO rmailbx=" << mRMailBx << " mailbx=" << mMailBx;
    return text.str();
}

/////////// RDataMR /////////////////

std::string RDataMR::asString() {
    std::ostringstream text;
    text << "<<MR newname=" << mName;
    return text.str();
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

std::string RDataMX::asString() {
    std::ostringstream text;
    text << "<<MX preference=" << mPreference << " exchange=" << mExchange;
    return text.str();
}

/////////// RDataNULL /////////////////

void RDataNULL::decode(Buffer &buffer, size_t dataSize) {
    auto *data = buffer.readBytes(dataSize);
    if (!data) return;
    mData.assign(data, data + dataSize);
}

void RDataNULL::encode(Buffer &buffer) {
    buffer.writeBytes(mData.data(), mData.size());
}

std::string RDataNULL::asString() {
    std::ostringstream text;
    text << "<<NULL size=" << mData.size();
    return text.str();
}

/////////// RDataNS /////////////////

std::string RDataNS::asString() {
    std::ostringstream text;
    text << "<<NS nsdname=" << mName;
    return text.str();
}

/////////// RDataPTR /////////////////

std::string RDataPTR::asString() {
    std::ostringstream text;
    text << "<<PTR ptrdname=" << mName;
    return text.str();
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

std::string RDataSOA::asString() {
    std::ostringstream text;
    text << "<<SOA mname=" << mMName << " rname=" << mRName << " serial=" << mSerial;
    text << " refresh=" << mRefresh << " retry=" << mRefresh << " retry=" << mRetry;
    text << " expire=" << mExpire << " minimum=" << mMinimum;
    return text.str();
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

std::string RDataTXT::asString() {
    std::ostringstream text;
    text << "<<TXT items=" << mTexts.size();
    for (auto it = mTexts.begin(); it != mTexts.end(); ++it)
        text << " '" << (*it) << "'";
    return text.str();
}

/////////// RDataA /////////////////

void RDataA::decode(Buffer &buffer, size_t /*dataSize*/) {
    // get data from buffer
    auto *data = buffer.readBytes(4);
    if (!data) return;

    memcpy(mAddr, data, 4);
}

void RDataA::encode(Buffer &buffer) {
    for (auto i = 0; i < 4; i++)
        buffer.writeUint8(mAddr[i]);
}

std::string RDataA::asString() {
    std::ostringstream text;
    text << "<<RData A addr=" << (uint32_t)mAddr[0] << '.' << (uint32_t)mAddr[1] << '.' << (uint32_t)mAddr[2] << '.' << (uint32_t)mAddr[3];
    return text.str();
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

std::string RDataWKS::asString() {
    std::ostringstream text;
    text << "<<RData WKS addr="<< (uint32_t)mAddr[0] << '.' << (uint32_t)mAddr[1] << '.' << (uint32_t)mAddr[2] << '.' << (uint32_t)mAddr[3];
    text << " protocol=" << mProtocol;
    text << " bitmap-size=" << mBitmap.size();
    return text.str();
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

std::string RDataAAAA::asString() {
    std::ostringstream text;
    text << "<<RData AAAA addr=";
    for (unsigned int i = 0; i < 16; i += 2) {
        if (i > 0)
            text << ':';

        text << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)mAddr[i];
        text << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)mAddr[i + 1];
    }
    return text.str();
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

std::string RDataNAPTR::asString() {
    std::ostringstream text;
    text << "<<NAPTR order=" << mOrder << " preference=" << mPreference << " flags=" << mFlags << " services="
         << mServices << " regexp=" << mRegExp << " replacement=" << mReplacement;
    return text.str();
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

std::string RDataSRV::asString() {
    std::ostringstream text;
    text << "mPriority: " << mPriority << ", mWeight: " << mWeight << ", mPort: " << mPort << ", mTarget: " << mTarget
         << std::endl;
    return text.str();
}


/////////// ResourceRecord ////////////

void ResourceRecord::decode(Buffer &buffer) {
    mName = buffer.readDomainName();
    auto dateType = (RecordDataType)buffer.readUint16();
    mClass = (RecordClass)buffer.readUint16();
    mTtl = buffer.readUint32();
    auto rDataSize = buffer.readUint16();
    if (rDataSize > 0) {
        switch (dateType) {
            case RDATA_CNAME:
                mRData = std::make_shared<RDataCNAME>();
                break;
            case RDATA_HINFO:
                mRData = std::make_shared<RDataHINFO>();
                break;
            case RDATA_MB:
                mRData = std::make_shared<RDataMB>();
                break;
            case RDATA_MD:
                mRData = std::make_shared<RDataMD>();
                break;
            case RDATA_MF:
                mRData = std::make_shared<RDataMF>();
                break;
            case RDATA_MG:
                mRData = std::make_shared<RDataMG>();
                break;
            case RDATA_MINFO:
                mRData = std::make_shared<RDataMINFO>();
                break;
            case RDATA_MR:
                mRData = std::make_shared<RDataMR>();
                break;
            case RDATA_MX:
                mRData = std::make_shared<RDataMX>();
                break;
            case RDATA_NS:
                mRData = std::make_shared<RDataNS>();
                break;
            case RDATA_PTR:
                mRData = std::make_shared<RDataPTR>();
                break;
            case RDATA_SOA:
                mRData = std::make_shared<RDataSOA>();
                break;
            case RDATA_TXT:
                mRData = std::make_shared<RDataTXT>();
                break;
            case RDATA_A:
                mRData = std::make_shared<RDataA>();
                break;
            case RDATA_WKS:
                mRData = std::make_shared<RDataWKS>();
                break;
            case RDATA_AAAA:
                mRData = std::make_shared<RDataAAAA>();
                break;
            case RDATA_NAPTR:
                mRData = std::make_shared<RDataNAPTR>();
                break;
            case RDATA_SRV:
                mRData = std::make_shared<RDataSRV>();
                break;
            default:
                mRData = std::make_shared<RDataNULL>();
        }

        // RData can refer to the offset after the rDataSize in buffer
        auto expectedEndPos = buffer.pos() + rDataSize;
        mRData->decode(buffer, rDataSize);
        if (buffer.pos() != expectedEndPos) {
            buffer.markBroken(BrokenReason::InvalidData);
        }
    }
}

void ResourceRecord::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
    buffer.writeUint16(mRData->getType());
    buffer.writeUint16(mClass);
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

std::string ResourceRecord::asString() {
    std::ostringstream text;
    //text << "<DNS RR: "  << mName << " rtype=" << mType << " rclass=" << mClass << " ttl=" << mTtl << " rdata=" <<  mRDataSize << " bytes ";
    if (mRData) {
        text << mRData->asString();
    }
    text << std::endl;
    return text.str();
}


