#include "MyHash.h"

MyHash::MyHash()
{
}

MyHash::~MyHash()
{
}

void MyHash::MyMD5(uchar * plaintext, uchar * hashcode)
{
	uchar tmp[512];
	MD5(plaintext, strlen((char *)plaintext), tmp);
	dump_hex(tmp, 16, hashcode);
}

void MyHash::MySha(uchar * plaintext, uchar * hashcode)
{
	uchar tmp[512];
	SHA1(plaintext, strlen((char *)plaintext), tmp);
	dump_hex(tmp, 20, hashcode);
}
