#include "BaseClass.h"

Crypto::Crypto()
{
}

Crypto::~Crypto()
{
}

void Crypto::dump_hex(unsigned char *src, int n, unsigned char *dest)
{
	for (int i = 0; i < n; ++i)
		sprintf_s((char *)&dest[i * 2], 2, "%02X", src[i]);
	// sprintf() will add '\0' automatically on the end of the string
}

void Crypto::scan_hex(unsigned char * src, int n, unsigned char * dest)
{
	unsigned int tmp;
	for (int i = 0; i < n; i++)
	{
		sscanf_s((char *)&src[i * 2], "%02X", &tmp);
		dest[i] = (unsigned char)tmp;
	}
}
