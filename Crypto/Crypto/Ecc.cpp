#include "resource.h"
#include "Ecc.h"

ECC::ECC()
{
}

ECC::~ECC()
{
}

void ECC::init(ECCInfo *ei)
{
	/* ��ʼ�������������� */
	a = BN_new();
	b = BN_new();
	p = BN_new();
	n = BN_new();
	k = BN_new();
	d = BN_new();
	Gx = BN_new();
	Gy = BN_new();
	Tx = BN_new();
	Ty = BN_new();
	ptext = BN_new();
	ctextr = BN_new();
	ctexts = BN_new();
	ctx = BN_CTX_new();

	BN_hex2bn(&a, ei->a);
	BN_hex2bn(&b, ei->b);
	BN_hex2bn(&p, ei->p);
	BN_hex2bn(&n, ei->n);
	BN_hex2bn(&Gx, ei->Gx);
	BN_hex2bn(&Gy, ei->Gy);
	BN_hex2bn(&d, ei->d);

	/* ��ʼ����Բ����Ⱥ */
	group = EC_GROUP_new(EC_GFp_mont_method());
	EC_GROUP_set_curve_GFp(group, p, a, b, ctx);

	/* ���û��� */
	G = EC_POINT_new(group);
	EC_POINT_set_affine_coordinates_GFp(group, G, Gx, Gy, ctx);
	EC_GROUP_set_generator(group, G, n, BN_value_one());

	T = NULL;
	R = NULL;
}

void ECC::free()
{
	BN_free(a);
	BN_free(b);
	BN_free(p);
	BN_free(n);
	BN_free(Gx);
	BN_free(Gy);
	BN_free(Tx);
	BN_free(Ty);
	BN_free(ptext);
	BN_free(d);
	BN_free(k);
	BN_free(ctextr);
	BN_free(ctexts);
	EC_POINT_free(G);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
	if (T) EC_POINT_free(T);
	if (R) EC_POINT_free(R);
}

void ECC::dump_group()
{
	puts("\n Curve defined by Weierstrass equation: y^2 = x^3 + a*x + b  (mod p)");
	printf(" A =              %s\n", BN_bn2hex(a));
	printf(" B =              %s\n", BN_bn2hex(b));
	printf(" P =              %s\n", BN_bn2hex(p));
	printf(" N =              %s\n", BN_bn2hex(n));
	printf(" Base point G = ( %s ,\n                  %s )\n", BN_bn2hex(Gx), BN_bn2hex(Gy));
	printf(" Cofactor = nPoints on curve / Order of G = %s\n", BN_bn2hex(BN_value_one()));
	printf(" Bits of n = %d\n\n", EC_GROUP_get_degree(group));
}

void ECC::encrypt(ECCInfo *ei, uchar *plaintext, Ciphertext *ct)
{
	if (plaintext == NULL)
		return;

	init(ei);

	dump_group();

	puts("\nEncrypting...\n");

	/* ��ȡ����Ϊ���� */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* ���㹫Կ */
	R = EC_POINT_new(group);
	EC_POINT_mul(group, R, d, NULL, NULL, ctx);

	/* ���������k */
	int ticks = (long)time(NULL);
	RAND_add(&ticks, sizeof(ticks), 1);		/* ������������ɵĲ���Ԥ֪�ԣ���buf������num������
											   ����PRNG�У�entropy�Ƕ�buf�����ݵ�����Թ���ֵ��
											   ���entropy ��num��ȣ���ôRAND_add������
											   Rand_seed������ͬ�� */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* ��������r */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_copy(ctextr, Tx);
	ct->r = (uchar *)BN_bn2hex(ctextr);

	/* ��������s */
	EC_POINT_mul(group, T, NULL, R, k, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_mul(ctexts, ptext, Tx, n, ctx);
	ct->s = (uchar *)BN_bn2hex(ctexts);

	free();
}

void ECC::decrypt(ECCInfo * ei, Ciphertext * ct, uchar * plaintext)
{
	if (ct->r == NULL || ct->s == NULL)
		return;

	init(ei);

	puts("\nDecrypting...\n");

	/* ��ȡr, sΪ���� */
	BN_hex2bn(&ctextr, (char *)(ct->r));
	BN_hex2bn(&ctexts, (char *)(ct->s));

	/* ����r������ */
	T = EC_POINT_new(group);
	EC_POINT_set_compressed_coordinates_GFp(group, T, ctextr, 0, ctx);

	/* ���� */
	EC_POINT_mul(group, T, NULL, T, d, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_inverse(Tx, Tx, n, ctx);
	BN_mod_mul(ptext, ctexts, Tx, n, ctx);
	
	/* ���� */
	uchar *ptext_hex;
	uint ptext_len;
	ptext_hex = (uchar *)BN_bn2hex(ptext);
	ptext_len = strlen((char *)ptext_hex);
	scan_hex(ptext_hex, ptext_len / 2, plaintext);
	plaintext[ptext_len / 2] = '\0';

	free();
}

void ECC::ecnr_signature(ECCInfo * ei, uchar * plaintext, Ciphertext * signature)
{
	if (plaintext == NULL)
		return;

	init(ei);

	puts("\nSigning by ECNR...\n");

	/* ��ȡ����Ϊ���� */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* ���������k */
	int ticks = (long)time(NULL);
	RAND_add(&ticks, sizeof(ticks), 1);
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* ����ǩ��r */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_add(ctextr, Tx, ptext);
	BN_mod(ctextr, ctextr, n, ctx);
	signature->r = (uchar *)BN_bn2hex(ctextr);

	/* ����ǩ��s */
	BN_mod_mul(ctexts, ctextr, d, n, ctx);
	BN_mod_sub(ctexts, k, ctexts, n, ctx);
	signature->s = (uchar *)BN_bn2hex(ctexts);

	free();
}

bool ECC::ecnr_validation(ECCInfo * ei, Ciphertext * signature, uchar * plaintext)
{
	if (signature->r == NULL || signature->s == NULL || plaintext == NULL)
		return false;

	init(ei);

	puts("\nValidating by ECNR...\n");

	/* ��ȡr, sΪ���� */
	BN_hex2bn(&ctextr, (char *)(signature->r));
	BN_hex2bn(&ctexts, (char *)(signature->s));

	/* ��ȡ����Ϊ���� */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* ���㹫Կ */
	R = EC_POINT_new(group);
	EC_POINT_mul(group, R, d, NULL, NULL, ctx);

	T = EC_POINT_new(group);
	/* �����֤ */
	EC_POINT_mul(group, T, ctexts, R, ctextr, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_sub(Tx, ctextr, Tx, n, ctx);

	if (BN_cmp(Tx, ptext) == 0)
		return true;

	return false;
}

void ECC::ecdsa_signature(ECCInfo * ei, uchar * plaintext, Ciphertext * signature)
{
	if (plaintext == NULL)
		return;

	init(ei);

	puts("\nSigning by ECDSA...\n");

	/* ��ȡ����Ϊ���� */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* ���������k */
	int ticks = (long)time(NULL);
	RAND_add(&ticks, sizeof(ticks), 1);
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* ����ǩ��r */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_copy(ctextr, Tx);
	signature->r = (uchar *)BN_bn2hex(ctextr);

	/* ����ǩ��s */
	BN_mod_mul(ctexts, ctextr, d, n, ctx);
	BN_mod_add(ctexts, ctexts, ptext, n, ctx);
	BN_mod_inverse(Tx, k, n, ctx);
	BN_mod_mul(ctexts, ctexts, Tx, n, ctx);
	signature->s = (uchar *)BN_bn2hex(ctexts);
}

bool ECC::ecdsa_validation(ECCInfo * ei, Ciphertext * signature, uchar * plaintext)
{
	if (signature->r == NULL || signature->s == NULL || plaintext == NULL)
		return false;

	init(ei);

	puts("\nValidating by ECDSA...\n");

	/* ��ȡr, sΪ���� */
	BN_hex2bn(&ctextr, (char *)(signature->r));
	BN_hex2bn(&ctexts, (char *)(signature->s));

	/* ��ȡ����Ϊ���� */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* ���㹫Կ */
	R = EC_POINT_new(group);
	EC_POINT_mul(group, R, d, NULL, NULL, ctx);

	T = EC_POINT_new(group);
	/* �����֤ */
	BN_mod_inverse(Tx, ctexts, n, ctx);
	BN_mod_mul(Ty, ctextr, Tx, n, ctx);
	BN_mod_mul(Tx, ptext, Tx, n, ctx);
	EC_POINT_mul(group, T, Tx, R, Ty, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	
	if (BN_cmp(Tx, ctextr) == 0)
		return true;

	return false;
}
