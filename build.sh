#!/bin/bash 

sudo apt-get install llvm
sudo apt install clang
sudo apt install linux-headers-`uname -r`
sudo apt install libbpf-dev

# for ubuntu
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

go generate && go build && sudo ./ebpf-ex1