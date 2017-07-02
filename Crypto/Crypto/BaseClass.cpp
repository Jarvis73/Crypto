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
		sprintf((char *)&dest[i * 2], "%02X", src[i]);
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

void Crypto::new_prime_bn(BIGNUM *ret, int bits)
{
	BN_GENCB *cb = NULL;

	if (!BN_generate_prime_ex(ret, bits, 1, NULL, NULL, cb))
	{
		printf("Generate false!!!");
		BN_hex2bn(&ret, "1");
	}
}

void Crypto::new_rand_bn(BIGNUM * ret, int bits)
{
	BN_rand(ret, bits, 0, 0);
}

void Crypto::new_psudo_rand_bn(BIGNUM * ret, int bits)
{
	BN_pseudo_rand(ret, bits, 0, 0);
}
