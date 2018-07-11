#include <stdio.h>
#include <string.h>

#include "../amb_packing/amb_packing.h"

#define DEBUG 0

#define ERROR_EXIT 0
#define SUCCESS_EXIT 0


int main(int argc, void** argv)
{
    if (argc <= 1)
    {
        printf("Error, no argument provided\n");
        return ERROR_EXIT;
    }
    else if (argc == 2) // one argument provided : keccak256 hash
    {
        char result[HASH_SIZE_STR];
        hash_keccak256_ETH_str((char *) argv[1], result);
        printf("0x%s\n", result);
    }
    else //2 argument : signature -> "hash", "private key"
    {
        char* hash = argv[1];
        char* pk = argv[2];
        
        if (hash[0] == '0' && hash[1] == 'x' && strlen(hash) == 66)
        {
            hash += 2;
#if DEBUG == 1
            printf("size of hash ok: %s\n", hash);
#endif
        }
        else if (hash[1] != 'x' && strlen(hash) == 64)
        {
#if DEBUG == 1
            printf("size of hash ok 2 : %s\n", hash);
#endif
        }
        else
        {
            printf("ERROR: hash size not good: %s\n", hash);
            return ERROR_EXIT;
        }
        
        if (pk[0] == '0' && pk[1] == 'x' && strlen(pk) == 66)
        {
            pk += 2;
#if DEBUG == 1
            printf("size of pk ok: %s\n", pk);
#endif
        }
        else if (pk[1] != 'x' && strlen(pk) == 64)
        {
#if DEBUG == 1
            printf("size of pk ok 2 : %s\n", pk);
#endif
        }
        else
        {
            printf("ERROR: private key size not good: %s\n", pk);
            return ERROR_EXIT;
        }
        
        char signature[SIGNATURE_SIZE_STR] = {0};
        int res = sign_str(hash, pk, signature);
        
        if (res == 0)
        {
            printf("An ERROR occured during the signing process");
            return ERROR_EXIT;
        }
        else
            printf("0x%s\n", signature);
        
        return SUCCESS_EXIT; //EXIT
    }
    
    return ERROR_EXIT;
}
