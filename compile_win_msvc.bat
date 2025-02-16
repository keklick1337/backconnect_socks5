del server_socks5.exe
del client_socks5.exe
del server_socks5.obj
del client_socks5.obj
cl /EHsc src/server_socks5.cpp /Feserver_socks5.exe ws2_32.lib
cl /EHsc src/client_socks5.cpp /Feclient_socks5.exe ws2_32.lib
