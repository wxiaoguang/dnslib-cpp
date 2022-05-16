/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>

#include "message.h"
#include "rr.h"
#include "buffer.h"

static int assertPass = 0, assertFail = 0;

#define TEST_ASSERT(exp) do { if ((exp)) { assertPass++; } else { assertFail++; std::cout << #exp << " failed" << std::endl; } } while(0)
#define TEST_ASSERT_EQUAL(a, b) do { if ((a) == (b)) { assertPass++; } else { assertFail++; std::cout << #a << " == " << #b << " failed. a=" << (a) << ", b=" << (b) << std::endl; } } while(0)

static void testBuffer() {
    // check decoding of character string
    char b1[] = {'\x05', 'h', 'e', 'l', 'l', 'o', '\x00', 'a', 'h', 'o', 'j'};
    dns::Buffer b(b1, sizeof(b1));

    std::string strCheck = b.readCharString();
    TEST_ASSERT(strCheck == "hello");

    strCheck = b.readCharString();
    TEST_ASSERT(strCheck.empty());

    // check decoding of domain name
    char b2[] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
    dns::Buffer buff2(b2, sizeof(b2) - 1);
    strCheck = buff2.readDomainName();
    TEST_ASSERT(strCheck == "www.google.com");
}

// check encoding of empty domain name
static void testBufferEmptyDomainName() {
    char buffer[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    dns::Buffer dnsBuffer(buffer, sizeof(buffer) - 1);
    dnsBuffer.writeDomainName("");
    TEST_ASSERT(buffer[0] == '\x00');
    TEST_ASSERT(buffer[1] == 'x');
}

// check encoding of domain name
static void testBufferDomainName() {
    char buffer[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    dns::Buffer dnsBuffer(buffer, sizeof(buffer) - 1);
    dnsBuffer.writeDomainName("abc.com");
    TEST_ASSERT(buffer[0] == '\x03');
    TEST_ASSERT(buffer[1] == 'a');
    TEST_ASSERT(buffer[2] == 'b');
    TEST_ASSERT(buffer[3] == 'c');
    TEST_ASSERT(buffer[4] == '\x03');
    TEST_ASSERT(buffer[5] == 'c');
    TEST_ASSERT(buffer[6] == 'o');
    TEST_ASSERT(buffer[7] == 'm');
    // check proper termination
    TEST_ASSERT(buffer[8] == '\x00');
    TEST_ASSERT(buffer[9] == 'x');
}

// check encoding of domain name which ends with '.'
static void testBufferDotEndedDomainName() {
    char buffer[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    dns::Buffer dnsBuffer(buffer, sizeof(buffer) - 1);
    dnsBuffer.writeDomainName("abc.com.");
    TEST_ASSERT(buffer[0] == '\x03');
    TEST_ASSERT(buffer[1] == 'a');
    TEST_ASSERT(buffer[2] == 'b');
    TEST_ASSERT(buffer[3] == 'c');
    TEST_ASSERT(buffer[4] == '\x03');
    TEST_ASSERT(buffer[5] == 'c');
    TEST_ASSERT(buffer[6] == 'o');
    TEST_ASSERT(buffer[7] == 'm');
    // check proper termination
    TEST_ASSERT(buffer[8] == '\x00');
    TEST_ASSERT(buffer[9] == 'x');
}

static void testBufferCharacterString() {
    // check encoding of domain name
    char b1[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    dns::Buffer buff1(b1, sizeof(b1) - 1);
    buff1.writeCharString("");
    TEST_ASSERT(b1[0] == '\x00');
    TEST_ASSERT(b1[1] == 'x');

    buff1.seek(0);
    buff1.writeCharString("ah");
    TEST_ASSERT(b1[0] == '\x02');
    TEST_ASSERT(b1[1] == 'a');
    TEST_ASSERT(b1[2] == 'h');
    TEST_ASSERT(b1[3] == 'x');
}

static void testCNAME_MB_MD_MF_MG_MR_NS_PTR() {
    char wireData[] = "\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";
    auto wireDataSize = sizeof(wireData) - 1;
    dns::Buffer buff(wireData, wireDataSize);

    dns::RDataCNAME rCNAME;
    rCNAME.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rCNAME.mName == "www.google.com");
    TEST_ASSERT(rCNAME.getType() == dns::RecordDataType::RDATA_CNAME);

    dns::RDataMB rMB;
    buff.seek(0);
    rMB.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rMB.mName == "www.google.com");
    TEST_ASSERT(rMB.getType() == dns::RecordDataType::RDATA_MB);

    dns::RDataMD rMD;
    buff.seek(0);
    rMD.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rMD.mName == "www.google.com");
    TEST_ASSERT(rMD.getType() == dns::RecordDataType::RDATA_MD);

    dns::RDataMF rMF;
    buff.seek(0);
    rMF.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rMF.mName == "www.google.com");
    TEST_ASSERT(rMF.getType() == dns::RecordDataType::RDATA_MF);

    dns::RDataMG rMG;
    buff.seek(0);
    rMG.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rMG.mName == "www.google.com");
    TEST_ASSERT(rMG.getType() == dns::RecordDataType::RDATA_MG);

    dns::RDataMR rMR;
    buff.seek(0);
    rMR.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rMR.mName == "www.google.com");
    TEST_ASSERT(rMR.getType() == dns::RecordDataType::RDATA_MR);

    dns::RDataNS rNS;
    buff.seek(0);
    rNS.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rNS.mName == "www.google.com");
    TEST_ASSERT(rNS.getType() == dns::RecordDataType::RDATA_NS);

    dns::RDataPTR rPTR;
    buff.seek(0);
    rPTR.decode(buff, wireDataSize);
    TEST_ASSERT(!buff.isBroken());
    TEST_ASSERT(rPTR.mName == "www.google.com");
    TEST_ASSERT(rPTR.getType() == dns::RecordDataType::RDATA_PTR);
}

static void testHINFO() {
    dns::RDataHINFO r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_HINFO);
}


static void testMINFO() {
    dns::RDataMINFO r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_MINFO);
}

static void testMX() {
    dns::RDataMX r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_MX);
}

static void testNULL() {
    dns::RDataUnknown r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_NULL);
}

static void testSOA() {
    dns::RDataSOA r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_SOA);
}

static void testTXT() {
    dns::RDataTXT r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_TXT);

    char txtData[] = {'\x02', '\x65', '\x65', '\x00'};
    dns::Buffer b1(txtData, sizeof(txtData));
    r.decode(b1, sizeof(txtData));
    TEST_ASSERT(!b1.isBroken());

    char txtData2[] = {'\x02', '\x65', '\x65', '\x03', '\x64', '\x64', '\x64', '\x00'};
    dns::Buffer b2(txtData2, sizeof(txtData2));
    r.decode(b2, sizeof(txtData2));
    TEST_ASSERT(!b2.isBroken());
}

static void testRDataA() {
    dns::RDataA r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_A);

    char addr[] = {'\x01', '\x02', '\x03', '\x04'};
    dns::Buffer b(addr, sizeof(addr));
    r.decode(b, sizeof(addr));
    TEST_ASSERT(!b.isBroken());

    uint8_t *addr2 = r.getAddress();
    TEST_ASSERT(addr2[0] == 1);
    TEST_ASSERT(addr2[1] == 2);
    TEST_ASSERT(addr2[2] == 3);
    TEST_ASSERT(addr2[3] == 4);

    b.seek(0);
    r.encode(b);
}

static void testWKS() {
    dns::RDataWKS r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_WKS);

    char wksData[] = {'\x01', '\x02', '\x03', '\x04', '\xaa', '\xff', '\xef'};
    dns::Buffer b(wksData, sizeof(wksData));
    r.decode(b, sizeof(wksData));

    TEST_ASSERT(!b.isBroken());
    TEST_ASSERT(r.mProtocol == 0xaa);
    TEST_ASSERT(r.mBitmap.size() == 2);

    b.seek(0);
    r.encode(b);
}

static void testRDataAAAA() {
    dns::RDataAAAA r;
    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_AAAA);

    char addr[] = {'\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10'};
    dns::Buffer b(addr, sizeof(addr));
    r.decode(b, sizeof(addr));
    TEST_ASSERT(!b.isBroken());

    uint8_t *addr2 = r.getAddress();
    for (auto i = 0; i < 16; i++)
        TEST_ASSERT(addr2[i] == i + 1);

    b.seek(0);
    r.encode(b);
}

static void testNAPTR() {
    dns::RDataNAPTR r;

    char naptr1[] = "\x00\x32\x00\x33\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x54\x00\x04\x5f\x73\x69\x70\x04\x5f\x74\x63\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00";
    dns::Buffer b(naptr1, sizeof(naptr1) - 1);
    r.decode(b, sizeof(naptr1) - 1);
    TEST_ASSERT(!b.isBroken());
    TEST_ASSERT(r.mOrder == 50);
    TEST_ASSERT(r.mPreference == 51);
    TEST_ASSERT(r.mFlags == "s");
    TEST_ASSERT(r.mServices == "SIP+D2T");
    TEST_ASSERT(r.mRegExp.empty());
    TEST_ASSERT(r.mReplacement == "_sip._tcp.icscf.brn56.iit.ims");
}

static void testSRV() {
    dns::RDataSRV r;
    char dasrv[] = "\x00\x14\x00\x00\x14\x95\x04\x61\x6c\x74\x32\x0b\x78\x6d\x70\x70\x2d\x73\x65\x72\x76\x65\x72\x01\x6c\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00";

    TEST_ASSERT(r.getType() == dns::RecordDataType::RDATA_SRV);
    dns::Buffer b(dasrv, sizeof(dasrv) - 1);
    r.decode(b, sizeof(dasrv) - 1);
    TEST_ASSERT(!b.isBroken());
    TEST_ASSERT(r.mPriority == 20);
    TEST_ASSERT(r.mWeight == 0);
    TEST_ASSERT(r.mPort == 5269);
    TEST_ASSERT(r.mTarget == "alt2.xmpp-server.l.google.com");
}

static void testPacket() {
    // check header without any queries and records
    char packet1[] = "\xd5\xad\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
    dns::Message m;
    TEST_ASSERT(m.decode(packet1, sizeof(packet1) - 1) == dns::BufferResult::NoError);
    TEST_ASSERT(m.mId == 0xd5ad);
    TEST_ASSERT(m.mOpCode == 0);
    TEST_ASSERT(m.mAA == 0);
    TEST_ASSERT(m.mTC == 0);
    TEST_ASSERT(m.mRD == 1);
    TEST_ASSERT(m.mRA == 1);
    TEST_ASSERT(m.mRCode == 0);
    TEST_ASSERT(m.questions.empty());
    TEST_ASSERT(m.answers.empty());
    TEST_ASSERT(m.authorities.empty());
    TEST_ASSERT(m.additions.empty());

    // check raw resource records
    char packet2[] = "\xd5\xad\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03\x77\x77\x77\x01\x6c\xc0\x10\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x68\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x63\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x67\xc0\x2c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x42\xf9\x5b\x93";
    m = dns::Message();
    TEST_ASSERT(m.decode(packet2, sizeof(packet2) - 1) == dns::BufferResult::NoError);
    TEST_ASSERT(m.questions.size() == 1);
    TEST_ASSERT(m.answers.size() == 5);
    TEST_ASSERT(m.authorities.empty());
    TEST_ASSERT(m.additions.empty());

    auto &qs = m.questions;
    TEST_ASSERT(qs[0].mType == dns::RecordDataType::RDATA_A);
    TEST_ASSERT(qs[0].mClass == dns::RecordClass::CLASS_IN);
    TEST_ASSERT(qs[0].mName == "www.google.com");

    auto &answers = m.answers;
    std::string expected[] = {
            "CNAME www.google.com IN 5 name=www.l.google.com",
            "A www.l.google.com IN 5 addr=66.249.91.104",
            "A www.l.google.com IN 5 addr=66.249.91.99",
            "A www.l.google.com IN 5 addr=66.249.91.103",
            "A www.l.google.com IN 5 addr=66.249.91.147",
    };
    for (size_t i = 0; i < answers.size(); i++) {
        TEST_ASSERT_EQUAL(answers[i].toDebugString(), expected[i]);
    }

    // check naptr resource records
    char packet3[] = "\x14\x38\x85\x80\x00\x01\x00\x03\x00\x00\x00\x00\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\x00\x23\x00\x01\xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2e\x00\x32\x00\x33\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x54\x00\x04\x5f\x73\x69\x70\x04\x5f\x74\x63\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\xc0\x4a\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2f\x00\x0a\x00\x0a\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x53\x00\x04\x5f\x73\x69\x70\x05\x5f\x73\x63\x74\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00\xc0\x85\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x2e\x00\x32\x00\x32\x01\x73\x07\x53\x49\x50\x2b\x44\x32\x55\x00\x04\x5f\x73\x69\x70\x04\x5f\x75\x64\x70\x05\x69\x63\x73\x63\x66\x05\x62\x72\x6e\x35\x36\x03\x69\x69\x74\x03\x69\x6d\x73\x00";
    m = dns::Message();
    TEST_ASSERT(m.decode(packet3, sizeof(packet3) - 1) == dns::BufferResult::NoError);
    TEST_ASSERT(m.questions.size() == 1);
    TEST_ASSERT(m.answers.size() == 3);
    TEST_ASSERT(m.authorities.empty());
    TEST_ASSERT(m.additions.empty());

    char packetSOA[] = "\x00\x00\x21\x00\x00\x01\x00\x01\x00\x00\x00\x00\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\x01\x00\x00\x0e\x10\x00\x36\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x77\x82\x0d\xbc\x00\x01\x51\x80\x00\x00\x1c\x20\x00\x36\xee\x80\x00\x02\xa3\x00";
    m = dns::Message();
    TEST_ASSERT(m.decode(packetSOA, sizeof(packetSOA) - 1) == dns::BufferResult::NoError);

    char packetHINFO[] = "\x00\x00\x29\x00\x00\x01\x00\x01\x00\x02\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x06\x00\xff\x00\x00\x0e\x10\x00\x00\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x0a\x01\x0b\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0d\x00\x01\x00\x00\x0e\x10\x00\x14\x09\x54\x65\x68\x6f\x6d\x79\x6c\x6c\x79\x09\x44\x4e\x53\x2d\x53\x75\x69\x74\x65\x0b\x68\x6f\x73\x74\x31\x2d\x68\x6f\x73\x74\x32\x00\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3a\x08\x68\x6d\x61\x63\x2d\x6d\x64\x35\x07\x73\x69\x67\x2d\x61\x6c\x67\x03\x72\x65\x67\x03\x69\x6e\x74\x00\x00\x00\x54\x3e\x33\x78\x01\x2c\x00\x10\x6f\xba\x22\x36\xf2\x25\xe2\x35\x13\x8f\x29\xbc\xa7\xb4\x89\x50\x00\x00\x00\x00\x00\x00";
    m = dns::Message();
    TEST_ASSERT(m.decode(packetHINFO, sizeof(packetHINFO) - 1) == dns::BufferResult::NoError);
    // TODO - compare values
}

static void testPacketInvalid() {
    char packet1[] = "\x00\x00\x01\x00\x00\x01\x00\x01\x00\x01\x00\x02\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x01\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x21\x00\x01\x00\x00\x0e\x10\x00\x08\x49\x00\x00\x00\x00\x00\xc8\x00\x01\x41\xc0\x2e\x00\x1e\x00\x01\x00\x00\x0e\x10\x00\x06\x01\x80\x00\x00\x00\x02\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x63\x00\x01\x00\x00\x0e\x10\x00\x0e\x0d\x76\x3d\x73\x70\x66\x31\x20\x65\x78\x70\x3a\x25\x1e\x0b\x68\x6f\x73\x74\x31\x2d\x68\x6f\x73\x74\x32\x00\x00\xfa\x00\xff\x00\x00\x00\x00\x00\x3a\x08\x68\x6d\x61\x63\x2d\x6d\x64\x35\x07\x73\x69\x67\x2d\x61\x6c\x67\x03\x72\x65\x67\x03\x69\x6e\x74\x00\x00\x00\x54\x3e\x44\xe5\x01\x2c\x00\x10\xe7\x01\x33\xed\x6a\x86\xab\x55\x30\xf3\xdd\xf1\x4f\x87\x9f\x6b\x00\x00\x00\x00\x00\x00";
    dns::Message m1;
    TEST_ASSERT(m1.decode(packet1, sizeof(packet1) - 1) != dns::BufferResult::NoError);

    char packet2[] = "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x01\x00\x01\x02\x31\x31\x01\x31\x02\x31\x30\x02\x31\x30\x07\x69\x6e\x2d\x61\x64\x64\x72\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0e\x00\x01\x00\x00\x0e\x10\x00\x30\x1c\x31\x27\x29\x29\x29\x20\x41\x4e\x44\x20\x28\x28\x28\x27\x66\x6f\x6f\x27\x20\x4c\x49\x4b\x45\x20\x27\x66\x6f\x6f\xc0\x12\x03\x64\x6e\x73\x05\x73\x75\x69\x74\x65\x05\x6c\x6f\x63\x61\x6c\x00\x00\x00\x29\x20\x00\x00\x00\x80\x00\x00\x00";
    dns::Message m2;
    TEST_ASSERT(m2.decode(packet2, sizeof(packet2) - 1) != dns::BufferResult::NoError);
}

static void testCreatePacket() {
    dns::Message answer;
    answer.mId = 45;
    answer.mQr = 1;

    // add NAPTR answer
    auto rr = dns::ResourceRecord();
    rr.mClass = dns::RecordClass::CLASS_IN;
    rr.mTtl = 60;

    auto rdata = std::make_shared<dns::RDataNAPTR>();
    rdata->mOrder = 50;
    rdata->mPreference = 51;
    rdata->mServices = "SIP+D2T";
    rdata->mRegExp = "";
    rdata->mReplacement = "_sip._tcp.icscf.brn56.iit.ims";
    rr.setRData(rdata);

    answer.answers.push_back(rr);

    size_t mesgSize;
    char mesg[2000];
    answer.encode(mesg, 2000, mesgSize);

    // todo check buffer
}

#define TEST(f) do { std::cout << "Run: "  << #f << std::endl; f(); } while(0)

int main() {
    TEST(testBuffer);
    TEST(testBufferEmptyDomainName);
    TEST(testBufferDomainName);
    TEST(testBufferDotEndedDomainName);
    TEST(testBufferCharacterString);
    TEST(testCNAME_MB_MD_MF_MG_MR_NS_PTR);
    TEST(testHINFO);
    TEST(testMINFO);
    TEST(testMX);
    TEST(testNULL);
    TEST(testSOA);
    TEST(testTXT);
    TEST(testWKS);
    TEST(testRDataA);
    TEST(testRDataAAAA);
    TEST(testNAPTR);
    TEST(testSRV);
    TEST(testPacket);
    TEST(testPacketInvalid);
    TEST(testCreatePacket);

    std::cout << "====" << std::endl;
    std::cout << "PASS: " << assertPass << ", FAIL: " << assertFail << std::endl;
    if (assertFail) {
        std::cerr << "Failed assertions: " << assertFail << std::endl;
    }
    return (assertPass != 0 && assertFail == 0) ? 0 : 1;
}
