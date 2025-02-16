#!/bin/bash
rm -rf server_socks5 client_socks5
g++ -std=c++20 src/server_socks5.cpp -o server_socks5 -pthread
g++ -std=c++20 src/client_socks5.cpp -o client_socks5 -pthread
