#include "MyHash.h"

int MD5Test()
{
	uchar hashcode[33];
	uchar plaintext[] = "My brother likes banana. A quick brown fox jump over the lazy dog.";
	printf("\n Original text is: %s\n", plaintext);

	MyHash md5_obj;

	md5_obj.MyMD5(plaintext, hashcode);

	printf("\n MD5 : %s\n\n", hashcode);

	return 0;
}

int ShaTest()
{
	uchar hashcode[41];
	uchar plaintext[] = "My brother likes banana. A quick brown fox jump over the lazy dog.";
	printf("\n Original text is: %s\n", plaintext);

	MyHash sha_obj;

	sha_obj.MySha(plaintext, hashcode);

	printf("\n SHA-1 : %s\n\n", hashcode);

	return 0;
}