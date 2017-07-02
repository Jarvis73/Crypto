#pragma once

#include "resource.h"
#include "BaseClass.h"

class MyHash : public Crypto
{
public:
	MyHash();
	~MyHash();
	void MyMD5(uchar *plaintext, uchar *hashcode);
};

/* MD5≤‚ ‘ */
int MD5Test();
