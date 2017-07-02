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
	EC_GROUP *group;		/* ������Բ����Ⱥ */
	EC_POINT *G, *T, *R;	/* ����, ��ʱ��, ��Կ�� */

	BN_CTX  *ctx;
	BIGNUM  *a,				/* ��Բ����ϵ��1 */
			*b,				/* ��Բ����ϵ��2 */
			*p,				/* ��Բ����ģ�� */
			*n,				/* ����Ľ��� */
			*Gx,			/* ��������� */
			*Gy,			/* ���������� */
			*Tx,			/* ��ʱ������� */
			*Ty;			/* ��ʱ�������� */
	BIGNUM  *ptext,			/* ���� -- plain text */
			*d,				/* ˽Կ */
			*k,				/* ����� */
			*ctextr,		/* ����0 -- cipher text r */
			*ctexts;		/* ����1 -- cipher text s */
};


/* ECC�㷨���� */
int EccTest();
