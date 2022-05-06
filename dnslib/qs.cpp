/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sstream>

#include "buffer.h"
#include "qs.h"

using namespace dns;

std::string QuerySection::asString() {
    std::ostringstream text;
    text << "<DNS Question: " << mName << " qtype=" << mType << " qclass=" << mClass << std::endl;
    return text.str();
}

void QuerySection::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
    buffer.writeUint16(mType);
    buffer.writeUint16(mClass);
}

