#pragma once
#include <stdio.h>


class Crypto
{
public:
	Crypto();
	~Crypto();
	void dump_hex(unsigned char *src, int n, unsigned char *dest);
	void scan_hex(unsigned char *src, int n, unsigned char *dest);
};