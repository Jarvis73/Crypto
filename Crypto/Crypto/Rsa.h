#pragma once

#include "resource.h"
#include "BaseClass.h"

/* Rsa算法类 */
class MyRSA : public Crypto
{
public:
	MyRSA();
	~MyRSA();
	/* 密钥生成 */
	void genRsaKey(int bits);
	/* 显示RSA参数 */
	void dump_rsa();
	/* RSA加密 */
	void encrypt(uchar *plaintext, uchar *ciphertext);
	/* RSA解密 */
	void decrypt(uchar *ciphertext, uchar *plaintext);

private:
	RSA *rsa;
};

/* RSA算法测试 */
int RsaTest();
