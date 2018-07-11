#include <stdio.h>
#include <string.h>

#include "../../insertion_sort/insertion_sort.h"

void print_result(char** data, uint* indices, uint size)
{
	printf(" ------------ init results -----------:\n");

	int i;

	for (i = 0 ; i < size*2 ; i+=2)
	{
		printf("%s : %s\n", data[i], data[i+1]);
	} 

	printf("\n ------------ sorted results -----------:\n");
	for (i = 0 ; i < size ; i++)
	{
		printf("%s : %s\n", data[indices[i]], data[indices[i]+1]);
	} 
}

int main()
{

#if 0
	// fail exemple
	{
		char* data[8] = {"type", "ambrosus.event.truc", "z-value", "249", "a-value", "215", "type", "truc"};
		uint indices[4] = {0, 2, 4, 6};
		printf("INIT OK \n");
		int res = insertion_sort( (const char **) data, indices, 4);
		printf("sorting res: %d\n", res);
		print_result(data, indices, 4);
	}
#endif

#if 0
	// good exemple with dif string sizes
	{
		char* data[] = {"type", "ambrosus.event.truc", "z-value", "249", "a-value", "215", "type2", "truc"};
		uint indices[] = {0, 2, 4, 6};
		int res = insertion_sort( (const char **) data, indices, 4);
		printf("sorting res: %d\n", res);
		print_result(data, indices, 4);
	}
#endif

#if 1
	// good exemple with a lot of strings
	{
		char* data[] = {"h", "h-bis", "y", "y-bis", "c", "c-bis", "a", "a-bis", "i", "i-bis", "v", "v-bis",
						"k", "k-bis", "t", "t-bis", "l", "l-bis", "w", "w-bis", "u", "u-bis", "x", "x-bis",
						"z", "z-bis", "b", "b-bis", "f", "f-bis", "s", "s-bis", "d", "d-bis", "q", "q-bis",
						"j", "j-bis", "m", "m-bis", "o", "o-bis", "r", "r-bis", "e", "e-bis", "p", "p-bis", 
						"g", "g-bis", "n", "n-bis"};

		uint indices[] = {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50};
		int res = insertion_sort( (const char **) data, indices, 26);
		printf("sorting res: %d\n", res);
		print_result(data, indices, 26);
	}
#endif

	return 1;
}
