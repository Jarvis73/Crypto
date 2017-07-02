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
	/* 初始化大数及上下文 */
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

	/* 初始化椭圆曲线群 */
	group = EC_GROUP_new(EC_GFp_mont_method());
	EC_GROUP_set_curve_GFp(group, p, a, b, ctx);

	/* 设置基点 */
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
	puts(  "***********************************************************************************\n*");
	puts(  "*  Elliptic Curve equation: y^2 = x^3 + a*x + b  (mod p)");
	printf("*  Coefficient A      = %s\n", BN_bn2hex(a));
	printf("*  Coefficient B      = %s\n", BN_bn2hex(b));
	printf("*  Module number P    = %s\n", BN_bn2hex(p));
	printf("*  Base point order N = %s\n", BN_bn2hex(n));
	printf("*  Base point Gx  = %s\n", BN_bn2hex(Gx));
	printf("*  Base point Gy  = %s\n", BN_bn2hex(Gy));
	printf("*  Cofactor           = %s\n", BN_bn2hex(BN_value_one()));
	printf("*  Bits of N          = %d\n", EC_GROUP_get_degree(group));
	puts(  "*\n***********************************************************************************");
}

void ECC::encrypt(uchar *plaintext, Ciphertext & ciphertext)
{
	if (plaintext == NULL)
		return;

	uchar *tmp;

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* 计算公钥 */
	R = EC_POINT_new(group);
	EC_POINT_mul(group, R, d, NULL, NULL, ctx);

	/* 产生随机数k */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* 计算密文r */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_copy(ctextr, Tx);
	tmp = (uchar *)BN_bn2hex(ctextr);
	strcpy_s((char *)ciphertext.r, strlen((char *)tmp) + 1, (char *)tmp);

	/* 计算密文s */
	EC_POINT_mul(group, T, NULL, R, k, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_mul(ctexts, ptext, Tx, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctexts);
	strcpy_s((char *)ciphertext.s, strlen((char *)tmp) + 1, (char *)tmp);
}

void ECC::decrypt(Ciphertext & ciphertext, uchar * plaintext)
{
	if (ciphertext.r == NULL || ciphertext.s == NULL)
		return;

	/* 读取r, s, Y2为大数 */
	BN_hex2bn(&ctextr, (char *)(ciphertext.r));
	BN_hex2bn(&ctexts, (char *)(ciphertext.s));

	/* 计算R点坐标 */
	T = EC_POINT_new(group);
	EC_POINT_set_compressed_coordinates_GFp(group, T, ctextr, 0, ctx);

	/* 解密 */
	EC_POINT_mul(group, T, NULL, T, d, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_inverse(Tx, Tx, n, ctx);
	BN_mod_mul(ptext, ctexts, Tx, n, ctx);
	
	/* 返回 */
	uchar *ptext_hex;
	uint ptext_len;
	ptext_hex = (uchar *)BN_bn2hex(ptext);
	ptext_len = strlen((char *)ptext_hex);
	scan_hex(ptext_hex, ptext_len / 2, plaintext);
	plaintext[ptext_len / 2] = '\0';
}

void ECC::ecnr_signature(uchar * plaintext, Ciphertext & signature)
{
	if (plaintext == NULL)
		return;

	uchar *tmp;

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* 产生随机数k */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* 计算签名r */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_add(ctextr, Tx, ptext, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctextr);
	strcpy_s((char *)signature.r, strlen((char *)tmp) + 1, (char *)tmp);

	/* 计算签名s, Y2 */
	BN_mod_mul(ctexts, ctextr, d, n, ctx);
	BN_mod_sub(ctexts, k, ctexts, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctexts);
	strcpy_s((char *)signature.s, strlen((char *)tmp) + 1, (char *)tmp);
}

bool ECC::ecnr_validation(Ciphertext & signature, uchar * plaintext)
{
	if (signature.r == NULL || signature.s == NULL || plaintext == NULL)
		return false;

	/* 读取r, s, Y2为大数 */
	BN_hex2bn(&ctextr, (char *)(signature.r));
	BN_hex2bn(&ctexts, (char *)(signature.s));

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* 计算公钥 */
	R = EC_POINT_new(group);
	EC_POINT_mul(group, R, d, NULL, NULL, ctx);

	T = EC_POINT_new(group);
	/* 身份验证 */
	EC_POINT_mul(group, T, ctexts, R, ctextr, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_sub(Tx, ctextr, Tx, n, ctx);

	if (BN_cmp(Tx, ptext) == 0)
		return true;

	return false;
}

void ECC::ecdsa_signature(uchar * plaintext, Ciphertext & signature)
{
	if (plaintext == NULL)
		return;

	uchar *tmp;

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* 产生随机数k */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* 计算签名r */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_copy(ctextr, Tx);
	tmp = (uchar *)BN_bn2hex(ctextr);
	strcpy_s((char *)signature.r, strlen((char *)tmp) + 1, (char *)tmp);

	/* 计算签名s */
	BN_mod_mul(ctexts, ctextr, d, n, ctx);
	BN_mod_add(ctexts, ctexts, ptext, n, ctx);
	BN_mod_inverse(Tx, k, n, ctx);
	BN_mod_mul(ctexts, ctexts, Tx, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctexts);
	strcpy_s((char *)signature.s, strlen((char *)tmp) + 1, (char *)tmp);
}

bool ECC::ecdsa_validation(Ciphertext & signature, uchar * plaintext)
{
	if (signature.r == NULL || signature.s == NULL || plaintext == NULL)
		return false;

	/* 读取r, s, Y2为大数 */
	BN_hex2bn(&ctextr, (char *)(signature.r));
	BN_hex2bn(&ctexts, (char *)(signature.s));

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptext);

	/* 计算公钥 */
	R = EC_POINT_new(group);
	EC_POINT_mul(group, R, d, NULL, NULL, ctx);

	T = EC_POINT_new(group);
	/* 身份验证 */
	BN_mod_inverse(Tx, ctexts, n, ctx);
	BN_mod_mul(Ty, ctextr, Tx, n, ctx);
	BN_mod_mul(Tx, ptext, Tx, n, ctx);
	EC_POINT_mul(group, T, Tx, R, Ty, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	
	if (BN_cmp(Tx, ctextr) == 0)
		return true;

	return false;
}
