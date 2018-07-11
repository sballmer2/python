// //////////////////////////////////////////////////////////
// keccak.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//
#pragma once
//#include "hash.h"
// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif
/// compute Keccak hash (designated SHA3)

#include "../constants.h"

enum CHAR_END_KECCAK256 { WITH_CHAR_END = 1, WITHOUT_CHAR_END = 0};


void keccak256_add_data(const void* data, uint numBytes);

void keccak256_reset_data();

void keccak256_get_hash(char result[HASH_HEX_SIZE]);

/*
/////// usage example 1:

//to perform hash of "hello":

//first perform reset data in order to remove internal remaining data
keccak256_reset_data();

// then add the data to hash:
char data[] = "hello";
keccak256_add_data(data, strlen(data));

// then get the hash computed:
char hash[HASH_SIZE_STR];
keccak256_get_hash_str(hash);

*/
