#pragma once

#include "resource.h"
#include "BaseClass.h"


/* ECC�㷨�� */
class ECC : public Crypto
{
public:
	ECC();
	~ECC();
	
	/* ��ʼ����Բ����Ⱥ */
	void init(ECCInfo *ei);
	/* �ͷ��ڴ� */
	void free();
	/* ��ʾ��Բ���߲��� */
	void dump_group();
	
	/* ECC���� */
	void encrypt(uchar *plaintext, Ciphertext & ciphertext);
	/* ECC���� */
	void decrypt(Ciphertext & ciphertext, uchar *plaintext);

	/* ECNR����ǩ�� */
	void ecnr_signature(uchar *plaintext, Ciphertext & signature);
	/* ECNR�����֤ */
	bool ecnr_validation(Ciphertext & signature, uchar *plaintext);

	/* ECDSA����ǩ�� */
	void ecdsa_signature(uchar *plaintext, Ciphertext & signature);
	/* ECDSA�����֤ */
	bool ecdsa_validation(Ciphertext & signature, uchar *plaintext);

private:
	EC_GROUP *group;			/* ������Բ����Ⱥ */
	EC_POINT *Alpha, *T, *Beta;	/* ����, ��ʱ��, ��Կ�� */

	BN_CTX  *ctx;
	BIGNUM  *a,				/* ��Բ����ϵ��1 */
			*b,				/* ��Բ����ϵ��2 */
			*p,				/* ��Բ����ģ�� */
			*n,				/* ����Ľ��� */
			*AlphaX,		/* ��������� */
			*AlphaY,		/* ���������� */
			*Tx,			/* ��ʱ������� */
			*Ty;			/* ��ʱ�������� */
	BIGNUM  *ptextX1,		/* ���� -- plain text x1 */
			*ptextX2,		/* ���� -- plain text x2 */
			*d,				/* ˽Կ */
			*k,				/* ����� */
			*ctextY0,		/* ����0 -- cipher text y0 */
			*ctextY1,		/* ����1 -- cipher text y1 */
			*ctextY2;		/* ����2 -- cipher text y2 */
};


/* ECC�㷨���� */
int EccTest();
