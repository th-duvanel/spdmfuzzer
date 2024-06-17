#pragma once

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <map>

#define ENDL '\n'

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

void fuzzerError(const char* message, int code);

void fuzzerConsole(const std::string message, char sign = 0);

void fuzzerConsole(const std::string message, const void* buffer, size_t size);

u64 randomize(u64 min, u64 max);