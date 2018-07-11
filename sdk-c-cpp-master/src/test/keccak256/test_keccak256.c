#include <stdio.h>
#include <string.h>

#include "../../keccak256/keccak256.h"

void test(const char* data_in, const char* expected_data)
{
	char hash[HASH_SIZE_STR];
	keccak256_reset_data();
	keccak256_add_data(data_in, strlen(data_in));
	keccak256_get_hash(hash);
	hash[HASH_SIZE_STR-1] = '\0';

	if (strcmp(hash, expected_data) == 0)
		printf(" ------------ TEST SUCCESS -------------\n");
	else
		printf(" ------------ TEST FAILURE -------------\n");

	printf("data in:  '%s'\nresult:   '%s'\nexpected: '%s'\n\n", data_in, hash, expected_data);

}

int main()
{
	test("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	test("hello", "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
	test("abcdefghijklmnopqrstuvwxyz0123456789", "3ba46239205c99cf86855a27bf111423600027de9b2346e33309fb9fa7e2fa9e");

	return 1;
}
