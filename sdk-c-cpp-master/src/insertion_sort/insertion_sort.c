#include <stdio.h>
#include <string.h>
#include <string.h>

#include "insertion_sort.h"

int insertion_sort(const char** data, uint* indices, uint indices_size)
{
	if (indices_size < 2)
		return 1;

	int i, j;

	for(i = indices_size-2; i > 0 ; i--)
	{
		for (j = 0 ; j <= i ; j++)
		{
			int comp = strcmp(data[indices[j]], data[indices[j+1]]);

			if (comp > 0) //data[j] is greater that data[j+1], need to be inversed
			{
				uint temp = indices[j];
				indices[j] = indices[j+1];
				indices[j+1] = temp;
			}
			else if (comp < 0)
			{
				// do nothing, the order is ok
			}
			else
			{
				// error, each key got to be different
				return 0;
			}
		}
	}

	return 1;
}