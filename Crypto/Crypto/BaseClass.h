#pragma once
#include <stdio.h>
#include "resource.h"

class Crypto
{
public:
	Crypto();
	~Crypto();
	
public:
	void dump_hex(unsigned char *src, int n, unsigned char *dest);
	void scan_hex(unsigned char *src, int n, unsigned char *dest);
	void new_prime_bn(BIGNUM * ret, int bits);
	void new_rand_bn(BIGNUM * ret, int bits);
	void new_psudo_rand_bn(BIGNUM * ret, int bits);
};