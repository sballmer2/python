
#include <stdint.h>

// Constants
#define HASH_HEX_SIZE 64
#define SIGNATURE_HEX_SIZE 130
#define ACCOUNT_HEX_SIZE 40

#define HASH_SIZE_STR (HASH_HEX_SIZE+1) // -> '\0'
#define SIGNATURE_SIZE_STR (SIGNATURE_HEX_SIZE+1) // -> '\0'
#define ACCOUNT_SIZE_STR (ACCOUNT_HEX_SIZE+1)

#define HASH_SIZE_0x_STR (HASH_SIZE_STR+2) // -> '0x'
#define SIGNATURE_SIZE_0x_STR (SIGNATURE_SIZE_STR+2) // -> '0x'
#define ACCOUNT_SIZE_0x_STR (ACCOUNT_SIZE_STR+2)

// for uint, one uint is [0-128] and one hex char is [0-16]
#define HASH_SIZE_UINT (HASH_HEX_SIZE/2)
#define SIGNATURE_SIZE_UINT (SIGNATURE_HEX_SIZE/2)

typedef uint32_t uint;

#define PRINTF_ALLOWED 1