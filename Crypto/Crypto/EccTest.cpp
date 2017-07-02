#include "Ecc.h"

#define PRIVATE_KEY "F29A69747FA97C3F2FF232F0F5D938E709A685BD8B35B392E699BBFB"

int EccTest()
{
	/* ������Բ���߲�������Դ�Դ����..\crypto\ec\ec_curve.c�л�ȡ */
	ECCInfo ei = {
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", // p
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", // a
		"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", // b
		"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", // Gx
		"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", // Gy
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", // n
		PRIVATE_KEY
	};

	ECC ecc;
	Ciphertext ciphertext;
	uchar plaintext[] = "My brother likes banana.";
	ciphertext.r = (uchar *)malloc(sizeof(uchar) * 512);
	ciphertext.s = (uchar *)malloc(sizeof(uchar) * 512);
	uchar decrypttext[512];
	
	ecc.init(&ei);
	ecc.dump_group();

	puts("\nEncrypting...\n");
	ecc.encrypt(plaintext, ciphertext);
	printf("r = %s\nY1 = %s\n", ciphertext.r, ciphertext.s);

	puts("\nDecrypting...\n");
	ecc.decrypt(ciphertext, decrypttext);
	printf("plaintext = %s\n", decrypttext);

	puts("\nSigning by ECNR...\n");
	ecc.ecnr_signature(plaintext, ciphertext);
	printf("r = %s\nY1 = %s\n", ciphertext.r, ciphertext.s);

	puts("\nValidating by ECNR...\n");
	if (ecc.ecnr_validation(ciphertext, plaintext))
		printf("Validation is successful!\n");
	else
		printf("Validation failed!\n");

	puts("\nSigning by ECDSA...\n");
	ecc.ecdsa_signature(plaintext, ciphertext);
	printf("r = %s\nY1 = %s\n", ciphertext.r, ciphertext.s);

	puts("\nValidating by ECDSA...\n");
	if (ecc.ecdsa_validation(ciphertext, plaintext))
		printf("Validation is successful!\n");
	else
		printf("Validation failed!\n");

	ecc.free();

	puts("\n");
	return 0;
}
