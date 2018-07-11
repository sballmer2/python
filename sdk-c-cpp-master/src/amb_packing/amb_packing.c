#include "amb_packing.h"

#include "../secp256k1/include/secp256k1_recovery.h"
#include "../secp256k1/src/secp256k1_c.h"
#include "../secp256k1/src/module/recovery/main_impl.h"

#include "../keccak256/keccak256.h"
#include "../constants.h"
#include "../insertion_sort/insertion_sort.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>



// Declarations
static int sign_raw(const uint8_t hash[HASH_SIZE_UINT], const uint8_t secret[HASH_SIZE_UINT], uint8_t result[SIGNATURE_SIZE_UINT]);

static void uint2char(const uint8_t* uint_data, char* char_data, size_t uint_length, int with_char_end);
static void char2uint(const char* char_data, uint8_t* uint_data, size_t uint_length);

// return the max number of array
static uint max(const uint* array, uint size);

// return if the string contain a number (int or float)
static int isNumber(const char* str);

//return how much char are required to put the number into strin, e.g: 5478 -> 4 char 
static uint number_char_size(int64_t number);

int make_asset_package(char* account, char* secret, uint64_t timestamp, uint32_t sequenceNumber, char* buffer_out, uint buffer_size)
{
	// verifications
	if (buffer_size < compute_asset_package_size(timestamp, sequenceNumber))
	{
#if PRINTF_ALLOWED
		printf("ERROR, you need to allocate more size for the asset. line %d, file %s\n", __LINE__, __FILE__);
#endif
		return ASSET_NOT_ENOUGH_OUPUT_SIZE;
	}


	/*
		{
			"assetId":"0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114",
			"content":{
				"idData":{
					"createdBy":"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D",
					"sequenceNumber":0,
					"timestamp":1523448160
				},
				"signature":"0xd52697b506d27db70bd40c24741e475f01c11f0f762b4adca6c5ca84bd7b905268b69eecdbf4f060cb292272ee5c0abd00b28d7205d1ee66e728eaf4f88baff71c"
			}
		}
	*/

	// pointer declarations
	uint buffer_ptr = 0,
		 buffer_ptr_assetId,
		 buffer_ptr_signature,
		 buffer_ptr_idData_start,
		 buffer_ptr_idData_stop,
		 buffer_ptr_content_start,
		 buffer_ptr_content_stop;
	
	// filling data
	buffer_ptr += sprintf(buffer_out + buffer_ptr,	"{"
														"\"assetId\":\"0x");
	buffer_ptr_assetId = buffer_ptr;

	buffer_ptr += sprintf(buffer_out + buffer_ptr, 			"1000000000000000000000000000000000000000000000000000000000000001\","
														"\"content\":");
	buffer_ptr_content_start = buffer_ptr;

	buffer_ptr += sprintf(buffer_out + buffer_ptr, 		"{"
															"\"idData\":");
	buffer_ptr_idData_start = buffer_ptr;

	buffer_ptr += sprintf(buffer_out + buffer_ptr, 			"{"
																"\"createdBy\":\"0x%.*s\","
																"\"sequenceNumber\":%d,"
																"\"timestamp\":%lu"
															"}", ACCOUNT_HEX_SIZE, account, sequenceNumber, timestamp);
	buffer_ptr_idData_stop = buffer_ptr;

	buffer_ptr += sprintf(buffer_out + buffer_ptr, 			",\"signature\":\"0x");
	buffer_ptr_signature = buffer_ptr;

	buffer_ptr += sprintf(buffer_out + buffer_ptr, 				"2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002\""
														"}");
	buffer_ptr_content_stop = buffer_ptr;
	
	buffer_out[buffer_ptr++] = 						'}';
	buffer_out[buffer_ptr] = '\0';

	// signature computing:
		// first hash idData, put result at the position of assetId (unused for now)
	hash_keccak256_ETH((const char*) (buffer_out + buffer_ptr_idData_start),
					   (uint)  (buffer_ptr_idData_stop - buffer_ptr_idData_start), 
					   (char*) (buffer_out + buffer_ptr_assetId));

		// crypt the hash of idData
	int signature_ok = sign(buffer_out + buffer_ptr_assetId, secret, buffer_out + buffer_ptr_signature);

	if (signature_ok == 0)
	{
#if PRINTF_ALLOWED
		printf("ERROR Signature couldn't be computed, at line %d of file %s\n", __LINE__, __FILE__);
#endif
		return ASSET_SIGNATURE_ERROR;
	}

	// Asset ID hash
	hash_keccak256_ETH(buffer_out + buffer_ptr_content_start, 
					   buffer_ptr_content_stop - buffer_ptr_content_start, 
					   buffer_out + buffer_ptr_assetId);

	return ASSET_NO_ERROR;
}

uint compute_asset_package_size(uint64_t timestamp, uint32_t sequenceNumber)
{
	/*
	How the asset is:
		{
			"assetId":"0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114",
			"content":{
				"idData":{
					"createdBy":"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D",
					"sequenceNumber":0,
					"timestamp":1523448160
				},
				"signature":"0xd52697b506d27db70bd40c24741e475f01c11f0f762b4adca6c5ca84bd7b905268b69eecdbf4f060cb292272ee5c0abd00b28d7205d1ee66e728eaf4f88baff71c"
			}
		}

	Full asset package size: 338 char +sequenceNumber size + timestamp size + '\0'
	{"assetId":"0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114","content":{"idData":{"createdBy":"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D","sequenceNumber":,"timestamp":},"signature":"0xd52697b506d27db70bd40c24741e475f01c11f0f762b4adca6c5ca84bd7b905268b69eecdbf4f060cb292272ee5c0abd00b28d7205d1ee66e728eaf4f88baff71c"}}
	*/

	return 338 + number_char_size(sequenceNumber) + number_char_size(timestamp) + 1;
}

uint compute_event_package_size(uint64_t timestamp, uint32_t accesslevel, const char** data[], uint data_size, const uint data_sizes[])
{
	/*
HOW the event is:

{
    "eventId": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "content": {
        "signature": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
        "idData": {
            "assetId": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "createdBy": "0xCA378C54D0B8BDB9deD565662388F25865b0fb9D",
            "accessLevel": 01234,
            "timestamp": 15000000000,
            "dataHash": "0x7d53fcaa152bcbf7a0e30d02c45398284918122377f34f5adde43d2708ff623b"
        },
        "data": [
            {
				"type": "ambrosus.event.customevent",
				"customField": "customValue",
				"customFiled2" : "another custom value"
            },
            {
				"type": "ambrosus.event.customevent",
				"customField": "customValue"
            }
        ]

    }
}

Full package with data = [] : 504 char + accesslevel size + timestamp size
{"eventId":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","content":{"signature":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01","idData":{"assetId":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","createdBy":"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D","accessLevel":01234,"timestamp":15000000000,"dataHash":"0x7d53fcaa152bcbf7a0e30d02c45398284918122377f34f5adde43d2708ff623b"},"data":[]}}

idData : 262
{"assetId":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef5","createdBy":"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D","accessLevel":01234,"timestamp":15000000000,"dataHash":"0x7d53fcaa152bcbf7a0e30d02c45398284918122377f34f5adde43d2708ff623b"}

content with data = [] : 430 char
{"signature":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01","idData":{"assetId":"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","createdBy":"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D","accessLevel":01234,"timestamp":15000000000,"dataHash":"0x7d53fcaa152bcbf7a0e30d02c45398284918122377f34f5adde43d2708ff623b"},"data":[]}



data_size = sum_data_str_only_content +  .................. (data content)
		    number_data_content/2 * 5 +  .................. (for the '"' and ':')
		    number_data_content_in_each - 1 +  ............ (for the ',') -> if each number of data is >0
		    number_of_each * 2 +  ......................... (for each '{' and '}')
		    number_of_each - 1 +  ......................... (for the ',' that separates the '{}') -> if number of each bigger than 0
		    	+ 1 for '\0' when alone


idData_size = 262 .................. with accesslevel in 5 decimals char and timestamp 11 decimals char (with 11 char, it can goes up to year 5138)
					+ 1 for '\0' when alone

content_size = 430 + data_size
					+ 1 for '\0' when alone

full_size = 504 + accesslevel size + timestamp size + data_size
					+ 1 for '\0' when alone

	*/

	uint data_size_computed = 0, i, j;

	for (i = 0 ; i < data_size ; i++)
	{
		uint nb_keys = data_sizes[i]/2;

		// for sum_data_str_only_content
		for (j=0 ; j < data_sizes[i] ; j++)
			data_size_computed += strlen(data[i][j]);

		// for the '"' and ':'
		data_size_computed += nb_keys * 5;

		// for the ',' in each
		if (data_sizes[i] > 1)
			data_size_computed += nb_keys-1;

		// for the '{}'
		data_size_computed += 2;

		// for each ',' between the '{}'
		if (i > 0)
			data_size_computed++;
    }

	// for the rest of the block
	data_size_computed += 504 + number_char_size(accesslevel) + number_char_size(timestamp);

	// for the very last '\0'
	data_size_computed += 1;

	return data_size_computed;
}


/*
 * assetId is of type: "3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114" -> 64 hex char + '\0'
 * account is of type: "CA378C54D0B8BDB9deD565662388F25865b0fb9D" -> 40 hex char + '\0'
 * secret  is of type: "2c8fb....................................................9fc1944" -> 64 hex char + '\0'
 * timestamp is a seconds timestamp from 1970
 * data is of type:[["type", "ambrosus.event.customevent", "customField", "customValue"], ["type", "ambrosus.event.customevent2", "customField", "customValue"]]
 *       -> must include pair amount of string in each box of the first array, must include "type" string 
 *           -> !!!! WONT BE CHECKED !!! 
 */
int make_event_package(const char* assetId, const char* account, const char* secret, uint64_t timestamp, uint32_t accesslevel, 
                       const char** data[], uint data_size, const uint data_sizes[], 
                       char* buffer_out, uint buffer_size)
{
	// size verification
	if (buffer_size < compute_event_package_size(timestamp, accesslevel, data, data_size, data_sizes))
	{
#if PRINTF_ALLOWED
		printf("Error, you need to set up more space for this event\n");
#endif
		return EVENT_NOT_ENOUGH_OUPUT_SIZE;
	}

	// data verifications
	int i, j;
	for (i = 0 ; i < data_size ; i++)
	{
		if (data_sizes[i] % 2) //if not an odd number
		{
			// the data need to be by 2 
#if PRINTF_ALLOWED
			printf("Error, data need to come 2 by 2. number %d is not odd\n", i);
#endif
			return EVENT_NO_ODD_NUMBER_OF_DATA;
		}

		int type_found = 0;
		for (j=0 ; j < data_sizes[i] ; j+=2)
		{
			if (strcmp(data[i][j], "type") == 0)
			{
				type_found = 1;
				break;
			}
		}

		if (!type_found)
		{
#if PRINTF_ALLOWED
			printf("Error, data need to each have the key 'type'\n");
#endif
			return EVENT_KEY_TYPE_MISSING;
		}
	}

		/* event example (sorted)
		{                          
		    "content": {
		    	"data": [
		            {
		              "type": "ambrosus.event.customevent",
		              "customField": "customValue"
		            }
		        ],
		        "idData": {
		        	"accessLevel": 4,
		            "assetId": "0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114",
		            "createdBy": "0xCA378C54D0B8BDB9deD565662388F25865b0fb9D",
		            "dataHash": "0x7d53fcaa152bcbf7a0e30d02c45398284918122377f34f5adde43d2708ff623b",
		            "timestamp": 1523450232
		        },
				"signature": "0x6bfbabd55e8fb6b48fa71f2ee557e1b4a58fd693888e7cdfa49c1ade56ca38184ac2d6d35795b06d0385ada5eee208ae10847b498bacf5127a5b646a34c4827b1b"
		    },
		    "eventId": "0x7e04d0b4b1b695a10412c958625afbfc58ddbba8b70fe0e3efc8d06781fbb272"
		}
		*/
	
	uint buffer_ptr = 0,

		 buffer_ptr_content_start,
		 buffer_ptr_content_stop,

		 buffer_ptr_data_start,
		 buffer_ptr_data_stop,

 		 buffer_ptr_idData_start,
		 buffer_ptr_idData_stop,

		 buffer_ptr_assetId, 
		 buffer_ptr_dataHash, 

		 buffer_ptr_signature, 
		 buffer_ptr_eventId;
	
	// filling struct
	{
		// filling beginning stuff
		buffer_ptr = sprintf(buffer_out, "{\"content\":");

		buffer_ptr_content_start = buffer_ptr;

		buffer_ptr += sprintf(buffer_out + buffer_ptr, "{\"data\":");

		// data sorting
		uint indices[data_size][max(data_sizes, data_size)/2];
		for (i = 0 ; i < data_size ; i++)
		{
			// init indices
			for (j = 0 ; j < data_sizes[i]/2 ; j++)
				indices[i][j] = 2*j;

			// sort indices using string data
			insertion_sort(data[i], indices[i], data_sizes[i]/2);
		}

		// filling data
		buffer_ptr_data_start = buffer_ptr;
		buffer_out[buffer_ptr++] = '[';
		for (i = 0 ; i < data_size ; i++)
		{
			buffer_out[buffer_ptr++] = '{';
			
			for (j = 0 ; j < data_sizes[i]/2 ; j++)
			{
				buffer_out[buffer_ptr++] = '"';

				buffer_ptr += sprintf(buffer_out + buffer_ptr, "%s", data[i][ (int64_t) indices[i][j]]);

				buffer_out[buffer_ptr++] = '"';
				buffer_out[buffer_ptr++] = ':';

				const char* str = data[i][ (int64_t) indices[i][j] + 1];
				if (isNumber(str))
				{
					buffer_ptr += sprintf(buffer_out + buffer_ptr, "%s", str);
				}
				else
				{
					buffer_out[buffer_ptr++] = '"';
					
					buffer_ptr += sprintf(buffer_out + buffer_ptr, "%s", str);

					buffer_out[buffer_ptr++] = '"';
				}
				
				if (j < data_sizes[i]/2 -1)
					buffer_out[buffer_ptr++] = ',';
			}

			buffer_out[buffer_ptr++] = '}';

			if (i < data_size-1)
				buffer_out[buffer_ptr++] = ',';
		}
		buffer_out[buffer_ptr++] = ']';
		buffer_ptr_data_stop = buffer_ptr;

		/*
		,
		        "idData": {
		        	"accessLevel": 4,
		            "assetId": "0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114",
		            "createdBy": "0xCA378C54D0B8BDB9deD565662388F25865b0fb9D",
		            "dataHash": "0x7d53fcaa152bcbf7a0e30d02c45398284918122377f34f5adde43d2708ff623b",
		            "timestamp": 1523450232
		        },
				"signature": "0x6bfbabd55e8fb6b48fa71f2ee557e1b4a58fd693888e7cdfa49c1ade56ca38184ac2d6d35795b06d0385ada5eee208ae10847b498bacf5127a5b646a34c4827b1b"
		    },
		    "eventId": "0x7e04d0b4b1b695a10412c958625afbfc58ddbba8b70fe0e3efc8d06781fbb272"
		}
		*/

		// filling idData
		buffer_ptr += sprintf(buffer_out + buffer_ptr, ",\"idData\":");

		buffer_ptr_idData_start = buffer_ptr;

		buffer_ptr += sprintf(buffer_out + buffer_ptr, "{"
														 "\"accessLevel\":%d,"
														 "\"assetId\":\"0x", accesslevel);

		buffer_ptr_assetId = buffer_ptr;

		buffer_ptr += sprintf(buffer_out + buffer_ptr,   "%.*s\","
														 "\"createdBy\":\"0x%.*s\","
														 "\"dataHash\":\"0x", HASH_HEX_SIZE, assetId, ACCOUNT_HEX_SIZE, account);

		buffer_ptr_dataHash = buffer_ptr;

		buffer_ptr += sprintf(buffer_out + buffer_ptr, "1000000000000000000000000000000000000000000000000000000000000001\","
														 "\"timestamp\":%lu"
													   "}", timestamp);

		buffer_ptr_idData_stop = buffer_ptr;

		// filling signature
		buffer_ptr += sprintf(buffer_out + buffer_ptr, ",\"signature\":\"0x");
		buffer_ptr_signature = buffer_ptr;
		buffer_ptr += sprintf(buffer_out + buffer_ptr, "2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002\"");

		buffer_out[buffer_ptr++] = '}';
		buffer_ptr_content_stop = buffer_ptr;

		// filling event ID
		buffer_ptr += sprintf(buffer_out + buffer_ptr, ",\"eventId\":\"0x");
		buffer_ptr_eventId = buffer_ptr;
		buffer_ptr += sprintf(buffer_out + buffer_ptr, "3000000000000000000000000000000000000000000000000000000000000003\"");

		buffer_out[buffer_ptr++] = '}';
		buffer_out[buffer_ptr] = '\0';
	}

	// data hash
	hash_keccak256_ETH((const char*) (buffer_out + buffer_ptr_data_start), 
					   (uint)  (buffer_ptr_data_stop - buffer_ptr_data_start), 
					   (char*) (buffer_out + buffer_ptr_dataHash));

	// signature
		// first hash idData, put result at the position of eventId (unused for now)
	hash_keccak256_ETH((const char*) (buffer_out + buffer_ptr_idData_start), 
					   (uint)  (buffer_ptr_idData_stop - buffer_ptr_idData_start), 
					   (char*) (buffer_out + buffer_ptr_eventId));

		// crypt the hash of idData
	int signature_ok = sign(buffer_out + buffer_ptr_eventId, secret, buffer_out + buffer_ptr_signature);

	if (signature_ok == 0)
	{
#if PRINTF_ALLOWED
		printf("ERROR Signature couldn't be computed, at line %d of file %s\n", __LINE__, __FILE__);
#endif
		return EVENT_SIGNATURE_ERROR;
	}

	// event ID hash
	hash_keccak256_ETH(buffer_out + buffer_ptr_content_start, 
					   buffer_ptr_content_stop - buffer_ptr_content_start, 
					   buffer_out + buffer_ptr_eventId);

	return EVENT_NO_ERROR;
}

void hash_keccak256(const char* data, uint data_size, char result[HASH_HEX_SIZE])
{
	// reset internal keccak data
	keccak256_reset_data();

	// add data
	keccak256_add_data(data, data_size);

	// get hash
	keccak256_get_hash(result);
}

void hash_keccak256_str(const char* data, char result[HASH_SIZE_STR])
{
	hash_keccak256(data, strlen(data), result);

	result[HASH_SIZE_STR-1] = '\0';
}

void hash_keccak256_ETH(const char* data, uint data_size, char result[HASH_HEX_SIZE])
{
	// reset internal keccak data
	keccak256_reset_data();

	// number of decimals character of data_size
	// e.g, if data_size = 250, data_size_dec will be (after while loop): 3
	uint data_size_dec = number_char_size(data_size);

	// ETH header string
	{
		char buf[27+data_size_dec];
		sprintf(buf, "%cEthereum Signed Message:\n%d", (char) 0x19, data_size);

		//add eth header
		keccak256_add_data(buf, strlen(buf));
	}

	// add full message next to header
	keccak256_add_data(data, data_size);

	// get hash
	keccak256_get_hash(result);
}

void hash_keccak256_ETH_str(const char* data, char result[HASH_SIZE_STR])
{
	hash_keccak256_ETH(data, strlen(data), result);

	result[HASH_SIZE_STR-1] = '\0';
}

int sign(const char hash[HASH_HEX_SIZE], const char secret[HASH_HEX_SIZE], char signature[SIGNATURE_HEX_SIZE])
{
	// compute uint hash
	uint8_t hash_uint[HASH_SIZE_UINT] = {0};
	char2uint(hash, hash_uint, HASH_SIZE_UINT);

	// compute uint secret
	uint8_t secret_uint[HASH_SIZE_UINT] = {0};
	char2uint(secret, secret_uint, HASH_SIZE_UINT);

	// signature uint buffer
	uint8_t sig_uint[SIGNATURE_SIZE_UINT] = {0};

	// compute signature
	if (sign_raw(hash_uint, secret_uint, sig_uint) == 0)
		return 0;

	// convert uint signature into char hex signature
	uint2char(sig_uint, signature, SIGNATURE_SIZE_UINT, WITHOUT_CHAR_END);

	return 1;
}

int sign_str(const char hash[HASH_SIZE_STR], const char secret[HASH_SIZE_STR], char signature[SIGNATURE_SIZE_STR])
{
	// compute signature
	if (sign(hash, secret, signature) == 0)
		return 0;

	signature[SIGNATURE_SIZE_STR-1] = '\0';

	return 1;
}

int sign_raw(const uint8_t hash[HASH_SIZE_UINT], const uint8_t secret[HASH_SIZE_UINT], uint8_t signature[SIGNATURE_SIZE_UINT])
{
	// static context (need to be init only once)
	static secp256k1_context *ctx = NULL;
	if (ctx == NULL)
		ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

	// setup data
	secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
	void* data_ = NULL;
	int recid[1] = {0};

	// setup signature data
	secp256k1_ecdsa_recoverable_signature sig;
	memset(&sig, 0, sizeof(sig));

	// compute signature
	if (secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, secret, noncefn, data_) == 0) 
		return 0;

	// store result
	secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &signature[0], &recid[0], &sig);

	signature[SIGNATURE_SIZE_UINT-1] = 27 + recid[0];

	return 1;
}

void uint2char(const uint8_t* uint_data, char* char_data, size_t uint_length, int with_char_end)
{
	int i;
	static char conv[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	for (i = 0 ; i < uint_length ; i++)
	{
		/*if (uint_data[i] <= 16)
			sprintf(char_data + 2*i, "0%x", uint_data[i]);
		else
			sprintf(char_data + 2*i, "%x", uint_data[i]);*/

		char_data[2*i]   = conv[uint_data[i] >> 4];
		char_data[2*i+1] = conv[uint_data[i] & 0x0F];
	}
	
	if (with_char_end != WITHOUT_CHAR_END)
		char_data[uint_length*2] = '\0';
}

void char2uint(const char* char_data, uint8_t* uint_data, size_t uint_length)
{
	int i;

	for (i = 0 ; i < uint_length ; i++)
	{
		uint_data[i] = 0;

		if (char_data[2*i] >= '0' && char_data[2*i] <= '9')
			uint_data[i] += (char_data[2*i] - '0')*16;
		else
			uint_data[i] += (char_data[2*i] - 'a' + 10)*16;

		if (char_data[2*i+1] >= '0' && char_data[2*i+1] <= '9')
			uint_data[i] += (char_data[2*i+1] - '0');
		else
			uint_data[i] += (char_data[2*i+1] - 'a' + 10);
	}
}

uint max(const uint* array, uint size)
{
	if (size == 0)
		return 0;

	uint max_value = 0, i;

	for (i = 0 ; i < size ; i++)
		max_value = array[i] > max_value ? array[i] : max_value;

	return max_value;
}

int isNumber(const char* str)
{
	int size = strlen(str), i, dot_counter = 0;

	for (i=0 ; i < size ; i++)
	{
		if (str[i] == '.')
		{
			if (dot_counter >= 1)
				return 0;

			dot_counter++;
		}
		else if (str[i] < '0' || str[i] > '9')
		{
			return 0;
		}
	}

	return 1;
}

uint number_char_size(int64_t number)
{
	if (number == 0)
		return 1;

	uint digit_number = 0;

	if (number < 0)
	{
		digit_number++;
		number = -number;
	}

	for (; number > 0 ; number/=10)
		digit_number++;

	return digit_number;
}