#pragma once
#include <Windows.h>

struct recv_shell {
    int receivedBytes;
    char* bufferReceivedBytes;
};

struct recv_shell start_listen(PCSTR port);
