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

/** @file
 *  This file contains the utility functions and definitions used in fuzzer.
 */

#define ENDL '\n'

#define u8  uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

/**
 * Error function that prints an error message and exits the program.
 * 
 * @param message Error message to be printed
 * @param code Error code to be printed
 */
void fuzzerError(const char* message, int code);

/**
 * Function that prints a message to the console in the specified standard.
 * 
 * @param message Message to be printed
 * @param sign Console type sign
 */
void fuzzerConsole(const char* message, char sign = '+');

/**
 * Function that prints a message to the console in the specified standard.
 * 
 * @param message Message to be printed
 * @param buffer Buffer added to the message to be printed
 * @param size Buffer's size
 */
void socketConsole(const char* message, void* buffer, size_t size);

/**
 * Function that prints a message to the console in the specified standard.
 * 
 * @param message Message to be printed
 * @param buffer Buffer added to the message to be printed
 * @param size Buffer's size
 */
u64 randomize(u64 min, u64 max);

/**
 * Function that assigns a value to a buffer in a specific position.
 * 
 * @param buffer Buffer to be assigned
 * @param pos Position in the buffer to be assigned
 * @param value Value to be assigned
 * @param size Size of the value to be assigned
 */
void assignBuffer(u8* buffer, u64 pos, u64 value, u8 size);