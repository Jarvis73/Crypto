#include "Rsa.h"

int RsaTest()
{
	MyRSA rsa;
	rsa.genRsaKey(256);
	rsa.dump_rsa();

	uchar plaintext[] = "My brother likes banana.";
	uchar ciphertext[1024];
	uchar decrypttext[1024];

	puts("\nEncrypting...\n");
	rsa.encrypt(plaintext, ciphertext);
	printf("ciphertext = %s\n", ciphertext);

	puts("\nDecrypting...\n");
	rsa.decrypt(ciphertext, decrypttext);
	printf("plaintext = %s\n\n", decrypttext);

	return 0;
}
