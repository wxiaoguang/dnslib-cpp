# DNS Protocol Library for C++ 11

<img src="https://github.com/wxiaoguang/dnslib-cpp/actions/workflows/cmake.yml/badge.svg" alt="badge">

## Introduction

A simple C++ library for encoding and decoding of DNS protocol packets.

This library is a full-rewritten of `mnezerka/dnslib`: adopt C++ 11 features, fix bugs, etc.
Since almost every line is changed, so I decided to create a new repository, instead of forking the original one.

Current implementation covers:

* RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
* RFC 2915 - The Naming Authority Pointer (NAPTR) DNS Resource Record
* RFC 3596 - DNS Extensions to Support IP Version 6

Other tests:

* checked with valgrind tool (``valgrind --leak-check=full ./unittests``)
* linted with cppcheck (``cppcheck --enable=all *cpp``)
* fake server tested against *Codenomicon DNS suite*

## Getting started

```shell
mkdir build && cd build
cmake ..
make
./unittests
```


## TODO

* [ ] Make the library CMake-friendly (eg: support FetchContent)
* [ ] Encoding/decoding TXT fields


## Licence

Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)

Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)

Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
