#pragma once
#include <algorithm>
#include <iostream>

char* getCmdOption(char** begin, char** end, const std::string& option);
bool cmdOptionExists(char** begin, char** end, const std::string& option);