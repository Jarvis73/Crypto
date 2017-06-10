#include "resource.h"
#include "Ecc.h"


int main()
{
	ECCInfo ei = {
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",	// a
		"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", // b
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",	// p
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", // n
		"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",	// Gx
		"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",	// Gy
		"CADDC27FEFC3040C1CCA194542218E002F58D504A639B668"	// d
	};

	ECC ecc;
	Ciphertext ciphertext;
	uchar plaintext[] = "My brother likes banana.";

	ecc.encrypt(&ei, plaintext, &ciphertext);
	printf("r = %s\ns = %s\n", ciphertext.r, ciphertext.s);

	uchar decrypttext[512];
	ecc.decrypt(&ei, &ciphertext, decrypttext);
	printf("plaintext = %s\n", decrypttext);

	ecc.ecnr_signature(&ei, plaintext, &ciphertext);
	printf("r = %s\ns = %s\n", ciphertext.r, ciphertext.s);

	if (ecc.ecnr_validation(&ei, &ciphertext, plaintext))
		printf("Validation is successful!\n");
	else
		printf("Validation failed!\n");

	ecc.ecdsa_signature(&ei, plaintext, &ciphertext);
	printf("r = %s\ns = %s\n", ciphertext.r, ciphertext.s);

	if (ecc.ecdsa_validation(&ei, &ciphertext, plaintext))
		printf("Validation is successful!\n");
	else
		printf("Validation failed!\n");

	puts("\n");
	return 0;
}
