/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#include "message.h"
#include "rr.h"

using namespace std;

#define MAX_MSG 2000

int main(int argc, char** argv) {
    int sockfd;

    struct sockaddr_in servaddr{};
    char bufRecv[MAX_MSG];
    char bufSend[MAX_MSG];

    if (argc != 2) {
        cout << "usage: fakecli <IP address>" << endl;
        return (1);
    }

    // prepare DNS query message

    dns::Message m;

    cout << "-------------------------------------------------------" << endl;
    cout << "Message prepared for sending:" << endl;
    cout << m.toDebugString() << endl;
    cout << "-------------------------------------------------------" << endl;

    // add NAPTR query
    auto qs = dns::QuestionSection("biloxi.ims", dns::RecordType::NAPTR);
    m.questions.emplace_back(std::move(qs));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);
    servaddr.sin_port = htons(6666);

    for (auto i = 0; i < 1000000; i++) {
        m.mId = i;

        size_t msgSize;
        m.encode(bufSend, MAX_MSG, msgSize);
        //cout << "sending " << msgSize << " bytes" << endl;
        sendto(sockfd, bufSend, msgSize, 0, (struct sockaddr *) &servaddr, sizeof(servaddr));

        //int n = recvfrom(sockfd, bufRecv, MAX_MSG, 0, NULL, NULL);
        recvfrom(sockfd, bufRecv, MAX_MSG, 0, nullptr, nullptr);

        if (i % 10000 == 0)
            cout << "iterations: " << i << endl;
    }
    return 0;
}
