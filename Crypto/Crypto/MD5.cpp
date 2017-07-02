#include "MD5.h"

MyMD5::MyMD5()
{
}

MyMD5::~MyMD5()
{
}

void MyMD5::hash(uchar * plaintext, uchar * hashcode)
{
	uchar tmp[512];
	MD5(plaintext, strlen((char *)plaintext), tmp);
	dump_hex(tmp, 16, hashcode);
}
