#pragma once

#include "resource.h"
#include "BaseClass.h"

/* Rsa�㷨�� */
class MyRSA : public Crypto
{
public:
	MyRSA();
	~MyRSA();
	/* ��Կ���� */
	void genRsaKey(int bits);
	/* ��ʾRSA���� */
	void dump_rsa();
	/* RSA���� */
	void encrypt(uchar *plaintext, uchar *ciphertext);
	/* RSA���� */
	void decrypt(uchar *ciphertext, uchar *plaintext);

private:
	RSA *rsa;
};

/* RSA�㷨���� */
int RsaTest();
