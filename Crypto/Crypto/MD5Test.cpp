#include "MD5.h"

int MD5Test()
{
	uchar hashcode[33];
	uchar plaintext[] = "My brother likes banana. A quick brown fox jump over the lazy dog.";
	printf("\n Original text is: %s\n", plaintext);

	MyMD5 md5_obj;

	md5_obj.hash(plaintext, hashcode);

	printf("\n The digest number is: %s\n\n", hashcode);

	return 0;
}