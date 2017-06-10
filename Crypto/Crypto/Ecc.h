#pragma once

#include "resource.h"
#include "BaseClass.h"

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
	void encrypt(ECCInfo *ei, uchar *plaintext, Ciphertext *ct);
	/* ECC���� */
	void decrypt(ECCInfo *ei, Ciphertext *ct, uchar *plaintext);

	/* ECNR����ǩ�� */
	void ecnr_signature(ECCInfo *ei, uchar *plaintext, Ciphertext *signature);
	/* ECNR�����֤ */
	bool ecnr_validation(ECCInfo *ei, Ciphertext *signature, uchar *plaintext);

	/* ECDSA����ǩ�� */
	void ecdsa_signature(ECCInfo *ei, uchar *plaintext, Ciphertext *signature);
	/* ECDSA�����֤ */
	bool ecdsa_validation(ECCInfo *ei, Ciphertext *signature, uchar *plaintext);

private:
	EC_GROUP *group;		/* ������Բ����Ⱥ */
	EC_POINT *G, *T, *R;	/* ����, ��ʱ��, ��Կ�� */

	BN_CTX  *ctx;
	BIGNUM  *a,				/* ��Բ����ϵ��1 */
			*b,				/* ��Բ����ϵ��2 */
			*p,				/* ��Բ����ģ�� */
			*n,				/* ��Բ���߽��� */
			*Gx,			/* ��������� */
			*Gy,			/* ���������� */
			*Tx,			/* ��ʱ������� */
			*Ty;			/* ��ʱ�������� */
	BIGNUM  *ptext,			/* ���� -- plain text */
			*d,				/* ˽Կ */
			*k,				/* ����� */
			*ctextr,		/* ����1 -- cipher text r */
			*ctexts;		/* ����2 -- cipher text s */
};
