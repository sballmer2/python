#ifndef AMB_PACKING_H
#define AMB_PACKING_H

#include "../constants.h"

enum ASSET_ERROR {ASSET_NO_ERROR = 1, ASSET_SIGNATURE_ERROR = 0, ASSET_NOT_ENOUGH_OUPUT_SIZE = -1};
enum EVENT_ERROR {EVENT_NO_ERROR = 1, EVENT_SIGNATURE_ERROR = 0, EVENT_NOT_ENOUGH_OUPUT_SIZE = -1, EVENT_NO_ODD_NUMBER_OF_DATA = -2, EVENT_KEY_TYPE_MISSING = -3};

/*
 * account is of type: "CA378C54D0B8BDB9deD565662388F25865b0fb9D" -> 40 hex char + '\0'
 * secret  is of type: "2c8fb....................................................9fc1944" -> 64 hex char + '\0'
 * timestamp is a seconds timestamp from 1970
 */
int make_asset_package(char* account, char* secret, uint64_t timestamp, uint32_t sequenceNumber, char* buffer_out, uint buffer_size);

/*
    compute the size (in byte) of the buffer to allocate in order to make an asset packages (the buffer to pass as buffer_out in make_event_package(...) )
*/
uint compute_asset_package_size(uint64_t timestamp, uint32_t sequenceNumber);


/*
 * assetId is of type: "3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114" -> 64 hex char + '\0'
 * account is of type: "CA378C54D0B8BDB9deD565662388F25865b0fb9D" -> 40 hex char + '\0'
 * secret  is of type: "2c8fb....................................................9fc1944" -> 64 hex char + '\0'
 * timestamp is a seconds timestamp from 1970
 * data is of type:[["type", "ambrosus.event.customevent", "customField", "customValue"], ["type", "ambrosus.event.customevent2", "customField", "customValue"]]
 *       -> must include pair amount of string in each box of the first array, must include "type" string 
 *           -> !!!! WONT BE CHECKED !!! 
 * with previous data, we have:
 * data_size = 2
 * data_sizes = [4, 4]
 */
int make_event_package(const char* assetId, const char* account, const char* secret, uint64_t timestamp, uint32_t accesslevel, 
                       const char** data[], uint data_size, const uint data_sizes[], 
                       char* buffer_out, uint buffer_size);

/*
    compute the size (in byte) of the buffer to allocate in order to make event packages (the buffer to pass as buffer_out in make_event_package(...) )
*/
uint compute_event_package_size(uint64_t timestamp, uint32_t accesslevel, const char** data[], uint data_size, const uint data_sizes[]);

/*
 * data is a simple string that doesn't necessarely end with '\0'
 * data_size is the size of data
 * result is the output buffer. No '\0' are going to be added
 */
void hash_keccak256(const char* data, uint data_size, char result[HASH_HEX_SIZE]);

/*
 * data is a simple string that ends with '\0'
 * result is the output buffer. A '\0' will be added.
 */
void hash_keccak256_str(const char* data, char result[HASH_SIZE_STR]);

/*
 * data is a simple string that doesn't necessarely end with '\0'
 * data_size is the size of data
 * result is the output buffer. No '\0' are going to be added
 *
 * this keccak hash add the official ethereum header before the hashing.
 * 	e.g : keccak256_ETH("hello") = keccak256("\x19Ethereum Signed Message:\n5hello")
 */
void hash_keccak256_ETH(const char* data, uint data_size, char result[HASH_HEX_SIZE]);

/*
 * data is a simple string that ends with '\0'
 * result is the output buffer. A '\0' will be added.
 *
 * this keccak hash add the official ethereum header before the hashing.
 * 	e.g : keccak256_ETH("hello") = keccak256("\x19Ethereum Signed Message:\n5hello")
 */
void hash_keccak256_ETH_str(const char* data, char result[HASH_SIZE_STR]);

/*
 * hash  is of type: "3d989373c0000000000000000000000000000000000000000000000000ad1114" -> 64 char
 * secret  is of type: "2c8fb00000000000000000000000000000000000000000000000000009fc1944" -> 64 char 
 * signature is the output of type: d52697b50......5d1ee66e728eaf4f88baff71c -> 130 char
 */
int sign(const char hash[HASH_HEX_SIZE], const char secret[HASH_HEX_SIZE], char signature[SIGNATURE_HEX_SIZE]);

/*
 * hash  is of type: "3d989373c0000000000000000000000000000000000000000000000000ad1114" -> 64 hex char + '\0' = 65 char
 * secret  is of type: "2c8fb00000000000000000000000000000000000000000000000000009fc1944" -> 64 hex char + '\0' = 65 char
 * signature is the output of type: d52697b50......5d1ee66e728eaf4f88baff71c -> 130 hex char + '\0' = 131 char
 */
int sign_str(const char hash[HASH_SIZE_STR], const char secret[HASH_SIZE_STR], char signature[SIGNATURE_SIZE_STR]);


#endif //AMB_PACKING_H