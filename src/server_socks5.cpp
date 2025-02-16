#include <iostream>
#include <thread>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <mutex>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef SOCKET SocketType;
  #define CLOSESOCK closesocket
  #define SOCKERROR WSAGetLastError()
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <netdb.h>
  typedef int SocketType;
  #define CLOSESOCK close
  #define INVALID_SOCKET -1
  #define SOCKERROR errno
#endif

static const int BACKLOG = 10;
static const int BUFFER_SIZE = 4096;
bool g_debug = false;

// Control channel
std::mutex g_mutex;              
SocketType g_natClientSock = INVALID_SOCKET;  
bool       g_natClientConnected = false;      

// Parameters
std::string g_xorKey;    // XOR key (mandatory)
std::string g_socksUser; // if not empty, enable SOCKS5 user/pass
std::string g_socksPass;

//------------------------------------------------------------------------------
// XOR encryption
//------------------------------------------------------------------------------
void xorData(char* data, int len, const std::string &key){
    if(key.empty()) return;
    for(int i = 0; i < len; i++){
        data[i] ^= key[i % key.size()];
    }
}

//------------------------------------------------------------------------------
// initSockets / cleanupSockets
//------------------------------------------------------------------------------
bool initSockets(){
#ifdef _WIN32
    WSADATA wd;
    int res = WSAStartup(MAKEWORD(2,2), &wd);
    if(res != 0){
        std::cerr << "[Server] WSAStartup error=" << res << "\n";
        return false;
    }
#endif
    return true;
}
void cleanupSockets(){
#ifdef _WIN32
    WSACleanup();
#endif
}

//------------------------------------------------------------------------------
// send/recv "raw"
bool sendAll(SocketType s, const char* data, int len){
    int total = 0;
    while(total < len){
        int sent = send(s, data + total, len - total, 0);
        if(sent <= 0) return false;
        total += sent;
    }
    return true;
}
bool recvAll(SocketType s, char* buf, int len){
    int total = 0;
    while(total < len){
        int r = recv(s, buf + total, len - total, 0);
        if(r <= 0) return false;
        total += r;
    }
    return true;
}

//------------------------------------------------------------------------------
// sendEnc / recvEnc (XOR)
bool sendEnc(SocketType s, const char* data, int len){
    if(s == INVALID_SOCKET) return false;
    std::vector<char> tmp(data, data + len);
    xorData(tmp.data(), len, g_xorKey);
    return sendAll(s, tmp.data(), len);
}

//------------------------------------------------------------------------------
// Creating a listening socket
//------------------------------------------------------------------------------
SocketType createListeningSocket(uint16_t port){
    SocketType sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == INVALID_SOCKET){
        std::cerr << "[Server] socket() error=" << SOCKERROR << "\n";
        return INVALID_SOCKET;
    }
    int opt = 1;
#ifdef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0){
        std::cerr << "[Server] bind error=" << SOCKERROR << "\n";
        CLOSESOCK(sock);
        return INVALID_SOCKET;
    }
    if(listen(sock, BACKLOG) < 0){
        std::cerr << "[Server] listen error=" << SOCKERROR << "\n";
        CLOSESOCK(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

//------------------------------------------------------------------------------
// SOCKS5 helpers
//------------------------------------------------------------------------------
static const unsigned char VER_SOCKS5 = 0x05;
static const unsigned char METHOD_NOAUTH = 0x00;
static const unsigned char METHOD_USERPASS = 0x02;
static const unsigned char METHOD_REJECT = 0xFF;

// (1) Select SOCKS5 method
bool socks5Handshake_SelectMethod(SocketType s, bool &useUserPass){
    unsigned char hdr[2];
    int r = recv(s, (char*)hdr, 2, 0);
    if(r < 2) return false;
    if(hdr[0] != VER_SOCKS5) return false;

    int nMethods = hdr[1];
    std::vector<unsigned char> methods(nMethods);
    r = recv(s, (char*)methods.data(), nMethods, 0);
    if(r < nMethods) return false;

    if(!g_socksUser.empty() || !g_socksPass.empty()){
        // Need authentication
        bool found = false;
        for(unsigned char m: methods){
            if(m == METHOD_USERPASS){
                found = true; 
                break;
            }
        }
        if(!found){
            unsigned char resp[2] = {VER_SOCKS5, METHOD_REJECT};
            sendAll(s, (char*)resp, 2);
            return false;
        }
        useUserPass = true;
        unsigned char resp[2] = {VER_SOCKS5, METHOD_USERPASS};
        sendAll(s, (char*)resp, 2);
    } else {
        // No auth
        bool found = false;
        for(unsigned char m: methods){
            if(m == METHOD_NOAUTH){
                found = true; 
                break;
            }
        }
        if(!found){
            unsigned char resp[2] = {VER_SOCKS5, METHOD_REJECT};
            sendAll(s, (char*)resp, 2);
            return false;
        }
        useUserPass = false;
        unsigned char resp[2] = {VER_SOCKS5, METHOD_NOAUTH};
        sendAll(s, (char*)resp, 2);
    }
    return true;
}

// (2) user/pass sub-negotiation
bool socks5Handshake_UserPass(SocketType s){
    unsigned char ver;
    if(recv(s, (char*)&ver, 1, 0) < 1) return false;
    if(ver != 0x01) return false;

    unsigned char ulen;
    if(recv(s, (char*)&ulen, 1, 0) < 1) return false;
    std::vector<char> uname(ulen);
    if(!recvAll(s, uname.data(), ulen)) return false;

    unsigned char plen;
    if(recv(s, (char*)&plen, 1, 0) < 1) return false;
    std::vector<char> upass(plen);
    if(!recvAll(s, upass.data(), plen)) return false;

    std::string su(uname.begin(), uname.end());
    std::string sp(upass.begin(), upass.end());

    unsigned char status = 0x00;
    if(su != g_socksUser || sp != g_socksPass){
        status = 0x01;
    }
    unsigned char resp[2] = {0x01, status};
    sendAll(s, (char*)resp, 2);

    return (status == 0x00);
}

// (3) parse CONNECT
bool socks5ParseConnect(SocketType s, uint32_t &ip, uint16_t &port){
    unsigned char hdr[4];
    if(!recvAll(s, (char*)hdr, 4)) return false;
    if(hdr[0] != 0x05) return false;
    if(hdr[1] != 0x01) return false; // CONNECT
    if(hdr[2] != 0x00) return false;

    unsigned char atyp = hdr[3];
    if(atyp == 0x01){
        // IPv4
        unsigned char a4[4];
        if(!recvAll(s, (char*)a4, 4)) return false;
        ip = (a4[0] << 24) | (a4[1] << 16) | (a4[2] << 8) | a4[3];
        unsigned char pbuf[2];
        if(!recvAll(s, (char*)pbuf, 2)) return false;
        port = (pbuf[0] << 8) | pbuf[1];
    } else if(atyp == 0x03){
        // domain
        unsigned char dlen;
        if(!recvAll(s, (char*)&dlen, 1)) return false;
        std::vector<char> dom(dlen + 1);
        if(!recvAll(s, dom.data(), dlen)) return false;
        dom[dlen] = '\0';

        unsigned char pbuf[2];
        if(!recvAll(s, (char*)pbuf, 2)) return false;
        port = (pbuf[0] << 8) | pbuf[1];

        struct hostent* he = gethostbyname(dom.data());
        if(!he) return false;
        struct in_addr** alist = (struct in_addr**)he->h_addr_list;
        if(!alist[0]) return false;
        ip = ntohl(alist[0]->s_addr);
    } else {
        return false;
    }
    return true;
}

// (4) send CONNECT reply
void socks5SendConnectReply(SocketType s, unsigned char rep, uint32_t ip = 0, uint16_t port = 0){
    unsigned char buf[10];
    buf[0] = 0x05;
    buf[1] = rep;
    buf[2] = 0x00;
    buf[3] = 0x01;
    uint32_t ip_n = htonl(ip);
    std::memcpy(buf + 4, &ip_n, 4);
    uint16_t p_n = htons(port);
    std::memcpy(buf + 8, &p_n, 2);
    sendAll(s, (char*)buf, 10);
}

//------------------------------------------------------------------------------
// handleSocksClient
//------------------------------------------------------------------------------
void handleSocksClient(SocketType sock){
    if(g_debug) std::cerr << "[Server] SOCKS client: start\n";
    bool useUserPass = false;
    if(!socks5Handshake_SelectMethod(sock, useUserPass)){
        if(g_debug) std::cerr << "[Server] SOCKS client: handshake fail\n";
        CLOSESOCK(sock);
        return;
    }
    if(useUserPass){
        if(!socks5Handshake_UserPass(sock)){
            if(g_debug) std::cerr << "[Server] SOCKS client: user/pass fail\n";
            CLOSESOCK(sock);
            return;
        }
    }

    uint32_t tip = 0;
    uint16_t tport = 0;
    if(!socks5ParseConnect(sock, tip, tport)){
        if(g_debug) std::cerr << "[Server] SOCKS client: parse CONNECT fail\n";
        socks5SendConnectReply(sock, 0x01);
        CLOSESOCK(sock);
        return;
    }

    // Create ephemeral socket
    SocketType epSock = socket(AF_INET, SOCK_STREAM, 0);
    if(epSock == INVALID_SOCKET){
        socks5SendConnectReply(sock, 0x01);
        CLOSESOCK(sock);
        return;
    }
    sockaddr_in ep;
    std::memset(&ep, 0, sizeof(ep));
    ep.sin_family = AF_INET;
    ep.sin_port = 0; // Let the OS pick a port
    ep.sin_addr.s_addr = INADDR_ANY;
    if(bind(epSock, (sockaddr*)&ep, sizeof(ep)) < 0){
        socks5SendConnectReply(sock, 0x01);
        CLOSESOCK(epSock);
        CLOSESOCK(sock);
        return;
    }
    if(listen(epSock, 1) < 0){
        socks5SendConnectReply(sock, 0x01);
        CLOSESOCK(epSock);
        CLOSESOCK(sock);
        return;
    }
    sockaddr_in tmp;
    socklen_t sz = sizeof(tmp);
    getsockname(epSock, (sockaddr*)&tmp, &sz);
    uint16_t ephemeralPort = ntohs(tmp.sin_port);

    if(g_debug){
        std::cerr << "[Server] SOCKS CONNECT to "
                  << ((tip >> 24) & 0xFF) << "." << ((tip >> 16) & 0xFF) << "." 
                  << ((tip >> 8) & 0xFF) << "." << (tip & 0xFF)
                  << ":" << tport << ", ephemeralPort=" << ephemeralPort << "\n";
    }

    bool okSend = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if(g_natClientSock != INVALID_SOCKET && g_natClientConnected){
            // Send 'C' command
            char cmd[1 + 2 + 4 + 2];
            cmd[0] = 'C';
            uint16_t ep_n = htons(ephemeralPort);
            std::memcpy(cmd + 1, &ep_n, 2);
            uint32_t tip_n = htonl(tip);
            std::memcpy(cmd + 3, &tip_n, 4);
            uint16_t tp_n = htons(tport);
            std::memcpy(cmd + 7, &tp_n, 2);
            okSend = sendEnc(g_natClientSock, cmd, sizeof(cmd));
        }
    }
    if(!okSend){
        if(g_debug) std::cerr << "[Server] Could not send 'C' command to NAT client\n";
        socks5SendConnectReply(sock, 0x05);
        CLOSESOCK(epSock);
        CLOSESOCK(sock);
        return;
    }

    // Wait for connection on epSock
    sockaddr_in from;
    socklen_t flen = sizeof(from);
    SocketType esock = accept(epSock, (sockaddr*)&from, &flen);
    CLOSESOCK(epSock);
    if(esock == INVALID_SOCKET){
        if(g_debug) std::cerr << "[Server] ephemeral accept fail\n";
        socks5SendConnectReply(sock, 0x05);
        CLOSESOCK(sock);
        return;
    }

    // Success
    socks5SendConnectReply(sock, 0x00, tip, tport);

    // Forward data in both directions
    std::thread tFwd([=](){
        char b[BUFFER_SIZE];
        while(true){
            int rx = recv(sock, b, BUFFER_SIZE, 0);
            if(rx <= 0) break;
            int tx = send(esock, b, rx, 0);
            if(tx <= 0) break;
        }
        CLOSESOCK(esock);
    });

    {
        char b[BUFFER_SIZE];
        while(true){
            int rx = recv(esock, b, BUFFER_SIZE, 0);
            if(rx <= 0) break;
            int tx = send(sock, b, rx, 0);
            if(tx <= 0) break;
        }
    }
    CLOSESOCK(esock);
    tFwd.join();
    CLOSESOCK(sock);
    if(g_debug) std::cerr << "[Server] SOCKS client: done\n";
}

//------------------------------------------------------------------------------
// Control channel: listen for NAT client, wait for HELLO (5s), then read (K - keepalive or EOF)
//------------------------------------------------------------------------------
#include <chrono>

static bool recvAllWithTimeout(SocketType s, char* buf, int len, int timeoutSec){
#ifdef _WIN32
    // On Windows: use SO_RCVTIMEO
    DWORD tmo = timeoutSec * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
#else
    // On Unix: also use SO_RCVTIMEO
    struct timeval tv;
    tv.tv_sec = timeoutSec; 
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
#endif
    int total = 0;
    while(total < len){
        int r = recv(s, buf + total, len - total, 0);
        if(r <= 0) return false;
        total += r;
    }
    // Disable timeout
#ifdef _WIN32
    DWORD zero = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&zero, sizeof(zero));
#else
    struct timeval tv0; 
    tv0.tv_sec = 0; 
    tv0.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv0, sizeof(tv0));
#endif
    return true;
}

void controlAcceptLoop(uint16_t cPort){
    SocketType listener = createListeningSocket(cPort);
    if(listener == INVALID_SOCKET){
        std::cerr << "[Server] Failed to listen on controlPort=" << cPort << "\n";
        return;
    }
    std::cout << "[Server] Waiting for NAT client on port " << cPort << "...\n";

    while(true){
        sockaddr_in caddr; 
        socklen_t clen = sizeof(caddr);
        SocketType cs = accept(listener, (sockaddr*)&caddr, &clen);
        if(cs == INVALID_SOCKET){
            std::cerr << "[Server] accept() error on control channel\n";
            break;
        }
        // Check if a client is already connected
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            if(g_natClientConnected){
                if(g_debug) std::cerr << "[Server] New NAT client, but already occupied.\n";
                const char msg[] = "OCCUP";
                sendEnc(cs, msg, (int)strlen(msg));
                CLOSESOCK(cs);
                continue;
            }
        }
        if(g_debug) std::cerr << "[Server] Control channel: connection accepted, waiting for HELLO\n";

        // Wait for 5 bytes of "HELLO" (5s timeout)
        char buf[16];
        std::memset(buf, 0, sizeof(buf));
        if(!recvAllWithTimeout(cs, buf, 5, 5)){
            if(g_debug) std::cerr << "[Server] Did not receive 'HELLO' (wrong key or no data)\n";
            CLOSESOCK(cs);
            continue;
        }
        // XOR
        xorData(buf, 5, g_xorKey);
        if(std::string(buf, 5) != "HELLO"){
            if(g_debug) std::cerr << "[Server] Received '" << std::string(buf, 5) << "' instead of 'HELLO'\n";
            CLOSESOCK(cs);
            continue;
        }
        if(g_debug) std::cerr << "[Server] Received HELLO => sending OK\n";
        const char msgOk[] = "OK";
        if(!sendEnc(cs, msgOk, 2)){
            if(g_debug) std::cerr << "[Server] Failed to send 'OK'\n";
            CLOSESOCK(cs);
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_natClientSock = cs;
            g_natClientConnected = true;
        }
        std::cout << "[Server] NAT client connected. (XOR key matched, handshake ok)\n";

        // Read data in loop: if 'K' (keepalive) - ignore; otherwise EOF => client disconnected
        while(true){
            char cc;
            int r = recv(cs, &cc, 1, 0);
            if(r <= 0){
                if(g_debug) std::cerr << "[Server] NAT client disconnected\n";
                CLOSESOCK(cs);
                std::lock_guard<std::mutex> lock(g_mutex);
                g_natClientSock = INVALID_SOCKET;
                g_natClientConnected = false;
                break;
            }
            // Decrypt
            cc ^= g_xorKey[0];
            if(cc == 'K'){
                // keep-alive
                if(g_debug) std::cerr << "[Server] Got keepalive (K)\n";
            } else {
                if(g_debug) std::cerr << "[Server] Unknown byte=" << (int)cc << "\n";
            }
        }
    }
    CLOSESOCK(listener);
}

//------------------------------------------------------------------------------
// Argument parser, main entry point
//------------------------------------------------------------------------------
static void printUsage(const char* prog){
    std::cout << "Usage (Server):\n"
              << prog << " -c <control_port> -S <socks_port> -x <xor_key> [-u <user> -p <pass>] [-d]\n"
              << "Example:\n"
              << prog << " -c 9000 -S 1080 -x secret -u test -p 123 -d\n";
}

int main(int argc, char* argv[]){
    if(!initSockets()){
        return 1;
    }
    uint16_t controlPort = 0, socksPort = 0;
    for(int i = 1; i < argc; i++){
        std::string arg = argv[i];
        if(arg == "-c"){
            if(i + 1 >= argc){ printUsage(argv[0]); return 0; }
            controlPort = (uint16_t)std::stoi(argv[++i]);
        } else if(arg == "-S"){
            if(i + 1 >= argc){ printUsage(argv[0]); return 0; }
            socksPort = (uint16_t)std::stoi(argv[++i]);
        } else if(arg == "-x"){
            if(i + 1 >= argc){ printUsage(argv[0]); return 0; }
            g_xorKey = argv[++i];
        } else if(arg == "-u"){
            if(i + 1 >= argc){ printUsage(argv[0]); return 0; }
            g_socksUser = argv[++i];
        } else if(arg == "-p"){
            if(i + 1 >= argc){ printUsage(argv[0]); return 0; }
            g_socksPass = argv[++i];
        } else if(arg == "-d"){
            g_debug = true;
        } else {
            printUsage(argv[0]);
            cleanupSockets();
            return 0;
        }
    }
    if(controlPort == 0 || socksPort == 0 || g_xorKey.empty()){
        printUsage(argv[0]);
        cleanupSockets();
        return 0;
    }

    // Start thread to accept NAT client
    std::thread tCtl(controlAcceptLoop, controlPort);

    // SOCKS5
    SocketType socksListener = createListeningSocket(socksPort);
    if(socksListener == INVALID_SOCKET){
        std::cerr << "[Server] Unable to listen on socksPort=" << socksPort << "\n";
        return 1;
    }
    std::cout << "[Server] SOCKS5 listening on port " << socksPort
              << ((!g_socksUser.empty() || !g_socksPass.empty()) 
                 ? " (auth=enabled)" : " (auth=disabled)")
              << ". XOR-key size=" << g_xorKey.size() << "\n";

    while(true){
        sockaddr_in saddr; 
        socklen_t slen = sizeof(saddr);
        SocketType c = accept(socksListener, (sockaddr*)&saddr, &slen);
        if(c == INVALID_SOCKET){
            if(g_debug) std::cerr << "[Server] accept() error on SOCKS\n";
            break;
        }
        if(g_debug) std::cerr << "[Server] New SOCKS client\n";
        std::thread th(handleSocksClient, c);
        th.detach();
    }

    CLOSESOCK(socksListener);
    tCtl.join();
    cleanupSockets();
    return 0;
}
