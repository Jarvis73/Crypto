#pragma once

#include "resource.h"
#include "BaseClass.h"

class MyMD5 : public Crypto
{
public:
	MyMD5();
	~MyMD5();
	void hash(uchar *plaintext, uchar *hashcode);
};

/* MD5≤‚ ‘ */
int MD5Test();
