#include <iostream>
#include <thread>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>

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
  #include <fcntl.h>
  #include <signal.h>
  typedef int SocketType;
  #define CLOSESOCK close
  #define INVALID_SOCKET -1
  #define SOCKERROR errno
#endif

#include <chrono>

//----------------------------------------------------------------
// Global settings
//----------------------------------------------------------------
bool g_debug=false;
std::string g_xorKey;
std::string g_serverIP;
uint16_t    g_controlPort=0;

//----------------------------------------------------------------
// XOR
//----------------------------------------------------------------
void xorData(char* data, int len, const std::string &key){
    if(key.empty()) return;
    for(int i=0; i<len; i++){
        data[i]^= key[i % key.size()];
    }
}

//----------------------------------------------------------------
// Sockets
//----------------------------------------------------------------
bool initSockets(){
#ifdef _WIN32
    WSADATA wd;
    int res=WSAStartup(MAKEWORD(2,2), &wd);
    if(res!=0){
        std::cerr<<"[Client] WSAStartup error="<<res<<"\n";
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

bool sendAll(SocketType s, const char* data, int len){
    int total=0;
    while(total<len){
        int sent=send(s,data+total,len-total,0);
        if(sent<=0) return false;
        total+=sent;
    }
    return true;
}
bool recvAll(SocketType s, char* buf, int len){
    int total=0;
    while(total<len){
        int r=recv(s, buf+total, len-total, 0);
        if(r<=0) return false;
        total+=r;
    }
    return true;
}

//----------------------------------------------------------------
// sendEnc/recvEnc
//----------------------------------------------------------------
bool sendEnc(SocketType s, const char* data, int len){
    std::vector<char> tmp(data,data+len);
    xorData(tmp.data(), len, g_xorKey);
    return sendAll(s, tmp.data(), len);
}

//----------------------------------------------------------------
// Connection to local IP:port
//  Attention: ip_n (network order), port_n (host order) => use htons(port_n)
//----------------------------------------------------------------
SocketType connectLocal(uint32_t ip_n, uint16_t port_n){
    SocketType ls=socket(AF_INET, SOCK_STREAM, 0);
    if(ls==INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in addr;
    std::memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr = ip_n; 
    addr.sin_port = htons(port_n);

    if(connect(ls,(sockaddr*)&addr,sizeof(addr))<0){
        CLOSESOCK(ls);
        return INVALID_SOCKET;
    }
    return ls;
}

//----------------------------------------------------------------
// Connection to server ephemeral port
//  port (host order) => use htons
//----------------------------------------------------------------
SocketType connectServerEphemeral(const std::string &ip, uint16_t port){
    SocketType s=socket(AF_INET, SOCK_STREAM, 0);
    if(s==INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in a;
    std::memset(&a,0,sizeof(a));
    a.sin_family=AF_INET;
    a.sin_port=htons(port);
    inet_pton(AF_INET, ip.c_str(), &a.sin_addr);
    if(connect(s,(sockaddr*)&a,sizeof(a))<0){
        CLOSESOCK(s);
        return INVALID_SOCKET;
    }
    return s;
}

//----------------------------------------------------------------
// Handling command 'C' (ephemeral)
//----------------------------------------------------------------
void handleCommandC(uint16_t ephemeralPort, uint32_t targetIP_n, uint16_t targetPort_h){
    // ephemeralPort — host order
    // targetIP_n    — network order
    // targetPort_h  — host order
    if(g_debug){
        std::cerr<<"[Client] handleCommandC: ephemeralPort="<<ephemeralPort
                 <<", target="<<inet_ntoa(*(in_addr*)&targetIP_n)
                 <<":"<<targetPort_h<<"\n";
    }
    // 1) Connect to the ephemeral port on the server
    SocketType esock = connectServerEphemeral(g_serverIP, ephemeralPort);
    if(esock==INVALID_SOCKET){
        std::cerr<<"[Client] Failed to connect to ephemeralPort="<<ephemeralPort<<"\n";
        return;
    }
    // 2) Local connection
    SocketType localSock=connectLocal(targetIP_n, targetPort_h);
    if(localSock==INVALID_SOCKET){
        std::cerr<<"[Client] Failed to connect locally: "
                 <<inet_ntoa(*(in_addr*)&targetIP_n)<<":"
                 <<targetPort_h<<"\n";
        CLOSESOCK(esock);
        return;
    }
    if(g_debug){
        std::cerr<<"[Client] handleCommandC: connection established\n";
    }

    // data forwarding
    std::thread tFwd([=](){
        char b[4096];
        while(true){
            int rx=recv(esock,b,4096,0);
            if(rx<=0) break;
            int tx=send(localSock,b,rx,0);
            if(tx<=0) break;
        }
        CLOSESOCK(localSock);
    });
    {
        char b[4096];
        while(true){
            int rx=recv(localSock,b,4096,0);
            if(rx<=0) break;
            int tx=send(esock,b,rx,0);
            if(tx<=0) break;
        }
    }
    CLOSESOCK(esock);
    tFwd.join();
    if(g_debug){
        std::cerr<<"[Client] handleCommandC: connection closed\n";
    }
}

//----------------------------------------------------------------
// Keep-Alive thread: send 'K' every 15 seconds
//----------------------------------------------------------------
void keepAliveThread(SocketType ctrlSock){
    while(true){
#ifdef _WIN32
        Sleep(15000);
#else
        sleep(15);
#endif
        char c='K';
        c ^= g_xorKey[0]; 
        int rc=send(ctrlSock,&c,1,0);
        if(rc<=0){
            if(g_debug) std::cerr<<"[Client] keepAliveThread: send failed => exiting\n";
            break;
        }
        if(g_debug) std::cerr<<"[Client] keepAliveThread: 'K' sent\n";
    }
}

//----------------------------------------------------------------
// Main control channel loop
//----------------------------------------------------------------
void controlChannelLoop(SocketType ctrl){
    // 1) Send "HELLO"
    if(g_debug) std::cerr<<"[Client] Sending HELLO\n";
    {
        char hello[5]={'H','E','L','L','O'};
        if(!sendEnc(ctrl, hello, 5)){
            if(g_debug) std::cerr<<"[Client] failed to send HELLO\n";
            return;
        }
    }
    // 2) Wait for response (OK / OCCUP)
    char resp[5];
    std::memset(resp,0,sizeof(resp));
    int r=recv(ctrl, resp, 5, 0);
    if(r<=0){
        if(g_debug) std::cerr<<"[Client] failed to read HELLO response\n";
        return;
    }
    // XOR-decode first r bytes
    for(int i=0; i<r; i++){
        resp[i]^= g_xorKey[i % g_xorKey.size()];
    }
    std::string sresp(resp,r);
    if(sresp=="OCCUP"){
        std::cerr<<"[Client] The server is already in use by another NAT client.\n";
        return;
    } else if(sresp!="OK"){
        if(g_debug) std::cerr<<"[Client] expected 'OK', but received '"<<sresp<<"'\n";
        return;
    }
    std::cout<<"[Client] XOR-handshake succeeded (received 'OK')\n";

    // Launch keep-alive thread
    std::thread kaThread(keepAliveThread, ctrl);

    // 3) Read commands (C ...), until the server disconnects
    while(true){
        char cmd;
        int rc=recv(ctrl, &cmd, 1, 0);
        if(rc<=0){
            if(g_debug) std::cerr<<"[Client] Control channel disconnected\n";
            break;
        }
        // XOR-decode cmd
        cmd ^= g_xorKey[0];
        if(cmd=='C'){
            // read another 8 bytes
            char buf[8];
            if(!recvAll(ctrl, buf, 8)){
                if(g_debug) std::cerr<<"[Client] Error in recvAll for command 'C'\n";
                break;
            }
            // XOR-decode
            for(int i=0; i<8; i++){
                buf[i]^= g_xorKey[(1+i) % g_xorKey.size()];
            }
            // buf[0..1] = ephemeralPort (network order)
            // buf[2..5] = targetIP (network order)
            // buf[6..7] = targetPort (network order)
            uint16_t ep_n;
            std::memcpy(&ep_n, buf, 2);
            uint16_t ephemeralPort = ntohs(ep_n);

            uint32_t tip_n;
            std::memcpy(&tip_n, buf+2, 4);
            // This IP is already in network order

            uint16_t tpt_n;
            std::memcpy(&tpt_n, buf+6, 2);
            uint16_t targetPort = ntohs(tpt_n);

            // start in a separate thread
            std::thread th(handleCommandC, ephemeralPort, tip_n, targetPort);
            th.detach();
        } else {
            // unknown command/byte
            if(g_debug) std::cerr<<"[Client] Unknown command="<<(int)cmd<<"\n";
            // we can simply ignore it
        }
    }

    // if disconnected => close socket, end keepAliveThread
    CLOSESOCK(ctrl);
    kaThread.join();
}

//----------------------------------------------------------------
// Reconnection loop
//----------------------------------------------------------------
void runClientLoop(){
    while(true){
        SocketType s=socket(AF_INET, SOCK_STREAM, 0);
        if(s==INVALID_SOCKET){
            std::cerr<<"[Client] socket() error\n";
#ifdef _WIN32
            Sleep(5000);
#else
            sleep(5);
#endif
            continue;
        }
        // connect
        sockaddr_in addr;
        std::memset(&addr,0,sizeof(addr));
        addr.sin_family=AF_INET;
        addr.sin_port=htons(g_controlPort);
        inet_pton(AF_INET, g_serverIP.c_str(), &addr.sin_addr);

        if(connect(s,(sockaddr*)&addr,sizeof(addr))<0){
            std::cerr<<"[Client] Failed to connect to "
                     <<g_serverIP<<":"<<g_controlPort<<". Retry in 5s.\n";
            CLOSESOCK(s);
#ifdef _WIN32
            Sleep(5000);
#else
            sleep(5);
#endif
            continue;
        }
        std::cout<<"[Client] Connected to "<<g_serverIP<<":"<<g_controlPort<<"\n";

        controlChannelLoop(s);

        std::cerr<<"[Client] Control connection closed. Retry in 5s...\n";
#ifdef _WIN32
        Sleep(5000);
#else
        sleep(5);
#endif
    }
}

//----------------------------------------------------------------
// Parser
//----------------------------------------------------------------
static void printUsage(const char* prog){
    std::cout<<"Usage (Client):\n"
             <<prog<<" -s <server_ip> -c <control_port> -x <xor_key> [-d]\n"
             <<"Example:\n"
             <<prog<<" -s 1.2.3.4 -c 9000 -x secret -d\n";
}

int main(int argc, char* argv[]){
    if(!initSockets()){
        return 1;
    }

    #ifndef _WIN32
      signal(SIGPIPE, SIG_IGN);
    #endif

    for(int i=1; i<argc; i++){
        std::string arg=argv[i];
        if(arg=="-s"){
            if(i+1>=argc){printUsage(argv[0]);return 0;}
            g_serverIP=argv[++i];
        } else if(arg=="-c"){
            if(i+1>=argc){printUsage(argv[0]);return 0;}
            g_controlPort=(uint16_t)std::stoi(argv[++i]);
        } else if(arg=="-x"){
            if(i+1>=argc){printUsage(argv[0]);return 0;}
            g_xorKey=argv[++i];
        } else if(arg=="-d"){
            g_debug=true;
        } else {
            printUsage(argv[0]);
            cleanupSockets();
            return 0;
        }
    }
    if(g_serverIP.empty()||g_controlPort==0||g_xorKey.empty()){
        printUsage(argv[0]);
        cleanupSockets();
        return 0;
    }

    runClientLoop();

    cleanupSockets();
    return 0;
}
