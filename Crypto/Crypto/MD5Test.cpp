#include "MyHash.h"

int MD5Test()
{
	uchar hashcode[33];
	uchar plaintext[] = "My brother likes banana. A quick brown fox jump over the lazy dog.";
	printf("\n Original text is: %s\n", plaintext);

	MyHash md5_obj;

	md5_obj.MyMD5(plaintext, hashcode);

	printf("\n The digest number is: %s\n\n", hashcode);

	return 0;
}