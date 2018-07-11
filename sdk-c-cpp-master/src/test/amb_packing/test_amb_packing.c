#include <stdio.h>
#include <string.h>

#include "../../amb_packing/amb_packing.h"


int main()
{
	//raw hash test
	{
		char hash[] = "data";
		char result[HASH_SIZE_STR];
		hash_keccak256_str(hash, result);

		printf("Raw hash of '%s' : %s\nexpect:              %s\n", hash, result, "8f54f1c2d0eb5771cd5bf67a6689fcd6eed9444d91a39e5ef32a9b4ae5ca14ff");

		if (strcmp(result, "8f54f1c2d0eb5771cd5bf67a6689fcd6eed9444d91a39e5ef32a9b4ae5ca14ff") == 0)
			printf(" ----------- TEST SUCCESS ------------- \n\n\n");
		else
			printf(" ----------- TEST FAILURE ------------- \n\n\n");
	}

	//ethereum hash test
	{
		char hash[] = "hello";
		char result[HASH_SIZE_STR];
		hash_keccak256_ETH_str(hash, result);

		printf("eth hash of '%s' is '\\x19Ethereum Signed Message:\\n5%s'\nresult:   %s\nexpected: %s\n", hash, hash, result, "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750");
		
		if (strcmp(result, "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750") == 0)
			printf(" ----------- TEST SUCCESS ------------- \n\n\n");
		else
			printf(" ----------- TEST FAILURE ------------- \n\n\n");
	}

	// sign test
	{
		char secret[] = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1";
		char hash[] = "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750";
		char signature[SIGNATURE_SIZE_STR] = {0};
		int res = sign_str(hash, secret, signature);

		printf("signature execution:%d\nresult:   %s\nexpected: %s\n", res, signature, "d79b9b05d1380109f53d140c200c310056ad7dcb44fcadf46371e623def7c6556b1a65678f851a5375a564e44f676769ede57f07ca611b1c976db98c7a9e4bbe1b");
	
		if (strcmp(signature, "d79b9b05d1380109f53d140c200c310056ad7dcb44fcadf46371e623def7c6556b1a65678f851a5375a564e44f676769ede57f07ca611b1c976db98c7a9e4bbe1b") == 0)
			printf(" ----------- TEST SUCCESS ------------- \n\n\n");
		else
			printf(" ----------- TEST FAILURE ------------- \n\n\n");
	}

	// make asset package
	{
		char account[] = "CA378C54D0B8BDB9deD565662388F25865b0fb9D";
		char secret[] = "2c8fbacbb4c0e754e238fe212279b621d6bc23d803257f928c3417fe99fc1944";

		uint buffer_size = compute_asset_package_size(1523448160, 0);
		char buf[buffer_size];

		char* real_asset =  "{"
								"\"assetId\":\"0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114\","
								"\"content\":{"
									"\"idData\":{"
										"\"createdBy\":\"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D\","
										"\"sequenceNumber\":0,"
										"\"timestamp\":1523448160"
									"},"
									"\"signature\":\"0xd52697b506d27db70bd40c24741e475f01c11f0f762b4adca6c5ca84bd7b905268b69eecdbf4f060cb292272ee5c0abd00b28d7205d1ee66e728eaf4f88baff71c\""
								"}"
							"}";

		make_asset_package(account, secret, 1523448160, 0, buf, buffer_size);


		printf("asset package:\n%s\n\nexpected package:\n%s\n\n", buf, real_asset);

		if (strcmp(buf, real_asset) == 0)
			printf(" ----------- TEST SUCCESS ------------- \n\n\n");
		else
			printf(" ----------- TEST FAILURE ------------- \n\n\n");

		printf("Size of the package returned: %ld\nSize of the Real expected package:%ld\nSize compute by compute_event_package_size():%d\n\n\n", strlen(buf), strlen(real_asset), buffer_size);

	}

	// make event package
	{
		const char account[] = "CA378C54D0B8BDB9deD565662388F25865b0fb9D";
		const char secret[] =  "2c8fbacbb4c0e754e238fe212279b621d6bc23d803257f928c3417fe99fc1944";
		const char assetId[] = "3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114";

		uint buf_size = 10000;
		char buf[buf_size];

		/* unsorted data:
		[
		    {
		        "a_value": "lol",
		        "type": "salut",
		        "z_value": 125.98
		    },
		    {
		        "a_value": "lol",
		        "type": "salut",
		        "v_value": 123,
		        "z_value": "x"
		    }
		}
		*/

		const char* frame_1[] = {"type", "salut", "a_value", "lol", "z_value", "125.98"};
		const char* frame_2[] = {"type", "salut", "a_value", "lol", "z_value", "x", "v_value", "123"};
		const char** data[2]= {frame_1, frame_2};

		uint data_size = 2;
		const uint data_sizes[2] = {6, 8};
		

		make_event_package(assetId, account, secret, 1523448160, 0, data, data_size, data_sizes, buf, buf_size);

		char* real_event = "{"
								"\"content\":{"
									"\"data\":["
										"{"
											"\"a_value\":\"lol\","
											"\"type\":\"salut\","
											"\"z_value\":125.98"
										"},"
										"{"
											"\"a_value\":\"lol\","
											"\"type\":\"salut\","
											"\"v_value\":123,"
											"\"z_value\":\"x\""
										"}"
									"],"
									"\"idData\":{"
										"\"accessLevel\":0,"
										"\"assetId\":\"0x3d989373c221927e4bb62d670b267e3063bfa0d77811b7328bbd42205bad1114\","
										"\"createdBy\":\"0xCA378C54D0B8BDB9deD565662388F25865b0fb9D\","
										"\"dataHash\":\"0x0809b4a78ce4d916663c7220235efabf4b67d5036069041bae40d9d0cd653939\","
										"\"timestamp\":1523448160"
									"},"
									"\"signature\":\"0x926246409e36bfbefd76c992ce168c5ae3059a636d5a6a0a9b1116d813757b7449e20a3e5266db86df16030c6a17c7ec49e696cac4bb7c3715277ce1e53b84061b\""
								"},"
								"\"eventId\":\"0x60844b4daceaa044f171d3268988e7112c3d0b827b8f4f1170693ddfd44096a1\""
							"}";

		printf("\nFull Event:\n%s\n", buf);
		if (strcmp(buf, real_event) == 0)
			printf(" ----------- TEST SUCCESS ------------- \n\n\n");
		else
			printf(" ----------- TEST FAILURE ------------- \n\n\n");

		printf("Size of the package returned: %ld\nSize of the Real expected package:%ld\nSize compute by compute_event_package_size():%d\n", strlen(buf), strlen(real_event), compute_event_package_size(1523448160, 0, data, data_size, data_sizes));
	}


	return 1;
}