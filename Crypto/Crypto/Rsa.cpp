#include "Rsa.h"

MyRSA::MyRSA()
{
	rsa = RSA_new();
}

MyRSA::~MyRSA()
{
}

void MyRSA::genRsaKey(int bits)
{
	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "10001");
	RSA_generate_key_ex(rsa, bits, e, NULL);
	BN_free(e);
}

void MyRSA::dump_rsa()
{
	puts("*************************************************************************\n*");
	printf("*  N = %s\n", BN_bn2hex(rsa->n)); 
	printf("*  P = %s\n", BN_bn2hex(rsa->p));
	printf("*  Q = %s\n", BN_bn2hex(rsa->q));
	printf("*  E = %s\n", BN_bn2hex(rsa->e));
	printf("*  D = %s\n", BN_bn2hex(rsa->d));
	puts("*\n*************************************************************************");
}

void MyRSA::encrypt(uchar * plaintext, uchar * ciphertext)
{
	BIGNUM *in = BN_new(), 
		*out = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	char *ctext;
	BN_bin2bn(plaintext, BN_num_bytes(rsa->n), in);
	BN_mod_exp(out, in, rsa->e, rsa->n, ctx);
	ctext = BN_bn2hex(out);
	strcpy_s((char *)ciphertext, BN_num_bytes(rsa->n) * 2 + 1, ctext);
	BN_free(in);
	BN_free(out);
	BN_CTX_free(ctx);
}

void MyRSA::decrypt(uchar * ciphertext, uchar * plaintext)
{
	BIGNUM *in = BN_new(),
		*out = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BN_hex2bn(&in, (char *)ciphertext);
	BN_mod_exp(out, in, rsa->d, rsa->n, ctx);
	BN_bn2bin(out, plaintext);
	BN_free(in);
	BN_free(out);
	BN_CTX_free(ctx);
}
