/// sha256.h : SHA256 Calculator
/// Based on NIST_FIPS 180-4 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
/// G.Ruiz 2025-03-05 v0.0
///


#pragma once


#include <stdint.h>
#include <math.h>


const int SHA256_BYTECOUNT = 32;


/// SHA256 Algorithm
/// uint8_t * msg : max 2^64 bytes
/// uint64_t msg_ByteSize : how many bytes are in msg
/// uint8_t * digest : a 32-byte uint8_t array
bool sha256( uint8_t * msg, uint64_t msg_ByteSize, uint8_t * digest );