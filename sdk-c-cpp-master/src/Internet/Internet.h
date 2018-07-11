#ifndef INTERNET_H
#define INTERNET_H

#include <stdint.h>
#include "../constants.h"

class Internet
{
	virtual Internet();
	virtual ~Internet();

	virtual int init_connection(const char* ssi, const char* password);
	virtual int reset_connection();
	virtual int stop_connection();

	virtual int send_data(const char* url, const char* data, const char* answer);
}

#endif //INTERNET_H
