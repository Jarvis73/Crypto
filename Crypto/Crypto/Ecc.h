#pragma once

#include "resource.h"
#include "BaseClass.h"


/* ECC算法类 */
class ECC : public Crypto
{
public:
	ECC();
	~ECC();
	
	/* 初始化椭圆曲线群 */
	void init(ECCInfo *ei);
	/* 释放内存 */
	void free();
	/* 显示椭圆曲线参数 */
	void dump_group();
	
	/* ECC加密 */
	void encrypt(uchar *plaintext, Ciphertext & ciphertext);
	/* ECC解密 */
	void decrypt(Ciphertext & ciphertext, uchar *plaintext);

	/* ECNR数字签名 */
	void ecnr_signature(uchar *plaintext, Ciphertext & signature);
	/* ECNR身份验证 */
	bool ecnr_validation(Ciphertext & signature, uchar *plaintext);

	/* ECDSA数字签名 */
	void ecdsa_signature(uchar *plaintext, Ciphertext & signature);
	/* ECDSA身份验证 */
	bool ecdsa_validation(Ciphertext & signature, uchar *plaintext);

private:
	EC_GROUP *group;		/* 定义椭圆曲线群 */
	EC_POINT *G, *T, *R;	/* 基点, 临时点, 公钥点 */

	BN_CTX  *ctx;
	BIGNUM  *a,				/* 椭圆曲线系数1 */
			*b,				/* 椭圆曲线系数2 */
			*p,				/* 椭圆曲线模数 */
			*n,				/* 基点的阶数 */
			*Gx,			/* 基点横坐标 */
			*Gy,			/* 基点纵坐标 */
			*Tx,			/* 临时点横坐标 */
			*Ty;			/* 临时点纵坐标 */
	BIGNUM  *ptext,			/* 明文 -- plain text */
			*d,				/* 私钥 */
			*k,				/* 随机数 */
			*ctextr,		/* 密文0 -- cipher text r */
			*ctexts;		/* 密文1 -- cipher text s */
};


/* ECC算法测试 */
int EccTest();
