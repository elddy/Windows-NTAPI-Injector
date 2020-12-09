#pragma once
#include <Windows.h>
#include <Urlmon.h>   // URLOpenBlockingStreamW()
#include <atlbase.h>  // CComPtr
#include <iostream>
#pragma comment( lib, "Urlmon.lib" )
using namespace std;

string download(const char URL[]);