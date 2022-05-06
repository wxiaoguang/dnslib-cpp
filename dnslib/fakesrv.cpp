/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sstream>
#include <cerrno>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <strings.h>
#include <getopt.h>

#include "message.h"
#include "rr.h"

using namespace std;

#define MAX_MSG 2000

#define VERSION_MAJOR 1
#define VERSION_MINOR 1

#define VERBOSITY_NONE "none"
#define VERBOSITY_BASIC "basic"

void displayUsage() {
    cout << "Fake DNS server" << endl;
    cout << "usage: fakesrv [-l ip ] [-p port] [-e level] [-h]" << endl;
    cout << " -l ip      ip address for listening (default is '127.0.0.1')" << endl;
    cout << " -p port    port for listening ((default is '53')" << endl;
    cout << " -e level   output verbosity level - 'all', 'basic', 'none' (default is 'all')" << endl;
    cout << " -h         show usage" << endl;
    cout << " -v         get version info" << endl;
}

int main(int argc, char **argv) {
    enum eVerbosityLevel {
        verbosityNone = 0, verbosityBasic, verbosityAll
    } verbosityLevel = verbosityAll;

    // ip address for listening
    std::string listenIp = "127.0.0.1";

    // port for listening
    unsigned int listenPort = 53;

    // message buffer
    char mesg[MAX_MSG];

    // parse cli arguments
    static const char *optString = "l:p:e:hv";
    int opt = getopt(argc, argv, optString);
    while (opt != -1) {
        switch (opt) {
            case 'l':
                listenIp = optarg;
                break;
            case 'e':
                if (strcmp(optarg, VERBOSITY_NONE) == 0) {
                    verbosityLevel = verbosityNone;
                } else if (strcmp(optarg, VERBOSITY_BASIC) == 0) {
                    verbosityLevel = verbosityBasic;
                } else
                    verbosityLevel = verbosityAll;
                break;
            case 'p': {
                // convert string value to int
                std::istringstream(optarg) >> listenPort;
                break;
            }
            case 'v':
                cout << "fakesrv version " << VERSION_MAJOR << "." << VERSION_MINOR << endl;
                return 0;
            case 'h':
            default:
                displayUsage();
                return 0;
        }
        opt = getopt(argc, argv, optString);
    }

    in_addr listenAddress = {0};
    if (inet_aton(listenIp.c_str(), &listenAddress) == 0) {
        cout << "Warning: Can't parse '" << listenIp << "' as an IP, will listen on '0.0.0.0' instead" << endl;
        listenAddress.s_addr = htonl(INADDR_ANY);
    }

    // create socket descriptor
    int sockfd;
    struct sockaddr_in servaddr{}, cliaddr{};
    socklen_t len;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        cout << "Error creating file descriptor" << endl;
        return 1;
    }
    if (verbosityLevel >= verbosityBasic)
        cout << "socket created (" << sockfd << ")" << endl;

    // bind socket to local address and port
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr = listenAddress;
    servaddr.sin_port = htons(listenPort);
    if (::bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1) {
        cout << "Error binding socket, addr: " << inet_ntoa(servaddr.sin_addr) << ":" << listenPort << ", fd:" << sockfd
             << " (" << strerror(errno) << ")" << endl;
        return 1;
    }
    if (verbosityLevel >= verbosityBasic)
        cout << "socket binded (port " << listenPort << ")" << endl;

    unsigned int i = 0;
    for (;;) {
        len = sizeof(cliaddr);
        auto n = recvfrom(sockfd, mesg, MAX_MSG, 0, (struct sockaddr *) &cliaddr, &len);
        if (n < 0) {
            break;
        }
        if (verbosityLevel >= verbosityBasic) {
            cout << "Received DNS packet (" << i << ") of size " << n << " bytes" << endl;
        }
        dns::Message m;
        if (!m.decode(mesg, n)) {
            cout << "DNS exception occured when parsing incoming data" << endl;
            continue;
        }

        if (verbosityLevel >= verbosityAll) {
            cout << "-------------------------------------------------------" << endl;
            cout << m.asString() << endl;
            cout << "-------------------------------------------------------" << endl;
        }

        // change type of message to response
        m.mQr = 1;

        // add NAPTR answer
        auto rr = dns::ResourceRecord();
        rr.mClass = dns::CLASS_IN;
        rr.mTtl = 1;
        auto rdata = std::make_shared<dns::RDataNAPTR>();
        rdata->mOrder = 1;
        rdata->mPreference = 1;
        rdata->mFlags = "u";
        rdata->mServices = "SIP+E2U";
        rdata->mRegExp = "!.*!domena.cz!";
        rdata->mReplacement = "";
        rr.setRData(rdata);
        m.answers.emplace_back(std::move(rr));

        // add A answer
        auto rrA = dns::ResourceRecord();
        rrA.mClass = dns::CLASS_IN;
        rrA.mTtl = 60;
        auto rdataA = std::make_shared<dns::RDataA>();
        uint8_t ip4[4] = {'\x01', '\x02', '\x03', '\x04' };
        rdataA->setAddress(ip4);
        rrA.setRData(rdataA);
        m.answers.emplace_back(std::move(rrA));


        size_t mesgSize;
        m.encode(mesg, MAX_MSG, mesgSize);

        if (verbosityLevel >= verbosityBasic)
            cout << "Sending DNS packet (" << i << ") of size " << mesgSize << " bytes" << endl;

        if (verbosityLevel >= verbosityAll) {
            cout << "-------------------------------------------------------" << endl;
            cout << m.asString() << endl;
            cout << "-------------------------------------------------------" << endl;
        }

        sendto(sockfd, mesg, mesgSize, 0, (struct sockaddr *) &cliaddr, sizeof(cliaddr));

        if (verbosityLevel >= verbosityNone) {
            if (i % 10000 == 0)
                cout << "iterations: " << i << endl;
        }
        i++;
    }
    return 0;
}
