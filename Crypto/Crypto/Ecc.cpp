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
	AlphaX = BN_new();
	AlphaY = BN_new();
	Tx = BN_new();
	Ty = BN_new();
	ptextX1 = BN_new();
	ptextX2 = BN_new();
	ctextY0 = BN_new();
	ctextY1 = BN_new();
	ctextY2 = BN_new();
	ctx = BN_CTX_new();

	BN_hex2bn(&a, ei->a);
	BN_hex2bn(&b, ei->b);
	BN_hex2bn(&p, ei->p);
	BN_hex2bn(&n, ei->n);
	BN_hex2bn(&AlphaX, ei->AlphaX);
	BN_hex2bn(&AlphaY, ei->AlphaY);
	BN_hex2bn(&d, ei->d);

	/* 初始化椭圆曲线群 */
	group = EC_GROUP_new(EC_GFp_mont_method());
	EC_GROUP_set_curve_GFp(group, p, a, b, ctx);

	/* 设置基点 */
	Alpha = EC_POINT_new(group);
	EC_POINT_set_affine_coordinates_GFp(group, Alpha, AlphaX, AlphaY, ctx);
	EC_GROUP_set_generator(group, Alpha, n, BN_value_one());

	T = NULL;
	Beta = NULL;
}

void ECC::free()
{
	BN_free(a);
	BN_free(b);
	BN_free(p);
	BN_free(n);
	BN_free(AlphaX);
	BN_free(AlphaY);
	BN_free(Tx);
	BN_free(Ty);
	BN_free(ptextX1);
	BN_free(ptextX2);
	BN_free(d);
	BN_free(k);
	BN_free(ctextY0);
	BN_free(ctextY1);
	BN_free(ctextY2);
	EC_POINT_free(Alpha);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
	if (T) EC_POINT_free(T);
	if (Beta) EC_POINT_free(Beta);
}

void ECC::dump_group()
{
	puts(  "***********************************************************************************\n*");
	puts(  "*  Curve defined by Weierstrass equation: y^2 = x^3 + a*x + b  (mod p)");
	printf("*  Coefficient A      = %s\n", BN_bn2hex(a));
	printf("*  Coefficient B      = %s\n", BN_bn2hex(b));
	printf("*  Module number P    = %s\n", BN_bn2hex(p));
	printf("*  Base point order N = %s\n", BN_bn2hex(n));
	printf("*  Base point AlphaX  = %s\n", BN_bn2hex(AlphaX));
	printf("*  Base point AlphaY  = %s\n", BN_bn2hex(AlphaY));
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
	BN_bin2bn(plaintext, BN_num_bytes(n), ptextX1);

	/* 计算公钥 */
	Beta = EC_POINT_new(group);
	EC_POINT_mul(group, Beta, d, NULL, NULL, ctx);

	/* 产生随机数k */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* 计算密文Y0 */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_copy(ctextY0, Tx);
	tmp = (uchar *)BN_bn2hex(ctextY0);
	strcpy_s((char *)ciphertext.Y0, strlen((char *)tmp) + 1, (char *)tmp);

	/* 计算密文Y1 */
	EC_POINT_mul(group, T, NULL, Beta, k, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_mul(ctextY1, ptextX1, Tx, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctextY1);
	strcpy_s((char *)ciphertext.Y1, strlen((char *)tmp) + 1, (char *)tmp);
}

void ECC::decrypt(Ciphertext & ciphertext, uchar * plaintext)
{
	if (ciphertext.Y0 == NULL || ciphertext.Y1 == NULL)
		return;

	/* 读取Y0, Y1, Y2为大数 */
	BN_hex2bn(&ctextY0, (char *)(ciphertext.Y0));
	BN_hex2bn(&ctextY1, (char *)(ciphertext.Y1));
///	BN_hex2bn(&ctextY2, (char *)(signature->Y2));

	/* 计算Beta点坐标 */
	T = EC_POINT_new(group);
	EC_POINT_set_compressed_coordinates_GFp(group, T, ctextY0, 0, ctx);

	/* 解密 */
	EC_POINT_mul(group, T, NULL, T, d, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_inverse(Tx, Tx, n, ctx);
	BN_mod_mul(ptextX1, ctextY1, Tx, n, ctx);
	
	/* 返回 */
	uchar *ptext_hex;
	uint ptext_len;
	ptext_hex = (uchar *)BN_bn2hex(ptextX1);
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
	BN_bin2bn(plaintext, BN_num_bytes(n), ptextX1);

	/* 产生随机数k */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* 计算签名Y0 */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_add(ctextY0, Tx, ptextX1, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctextY0);
	strcpy_s((char *)signature.Y0, strlen((char *)tmp) + 1, (char *)tmp);

	/* 计算签名Y1, Y2 */
	BN_mod_mul(ctextY1, ctextY0, d, n, ctx);
	BN_mod_sub(ctextY1, k, ctextY1, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctextY1);
	strcpy_s((char *)signature.Y1, strlen((char *)tmp) + 1, (char *)tmp);
}

bool ECC::ecnr_validation(Ciphertext & signature, uchar * plaintext)
{
	if (signature.Y0 == NULL || signature.Y1 == NULL || plaintext == NULL)
		return false;

	/* 读取Y0, Y1, Y2为大数 */
	BN_hex2bn(&ctextY0, (char *)(signature.Y0));
	BN_hex2bn(&ctextY1, (char *)(signature.Y1));
///	BN_hex2bn(&ctextY2, (char *)(signature->Y2));

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptextX1);

	/* 计算公钥 */
	Beta = EC_POINT_new(group);
	EC_POINT_mul(group, Beta, d, NULL, NULL, ctx);

	T = EC_POINT_new(group);
	/* 身份验证 */
	EC_POINT_mul(group, T, ctextY1, Beta, ctextY0, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_mod_sub(Tx, ctextY0, Tx, n, ctx);

	if (BN_cmp(Tx, ptextX1) == 0)
		return true;

	return false;
}

void ECC::ecdsa_signature(uchar * plaintext, Ciphertext & signature)
{
	if (plaintext == NULL)
		return;

	uchar *tmp;

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptextX1);

	/* 产生随机数k */
	BN_rand(k, BN_num_bits(n), 0, 0);

	/* 计算签名Y0 */
	T = EC_POINT_new(group);
	EC_POINT_mul(group, T, k, NULL, NULL, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	BN_copy(ctextY0, Tx);
	tmp = (uchar *)BN_bn2hex(ctextY0);
	strcpy_s((char *)signature.Y0, strlen((char *)tmp) + 1, (char *)tmp);

	/* 计算签名s */
	BN_mod_mul(ctextY1, ctextY0, d, n, ctx);
	BN_mod_add(ctextY1, ctextY1, ptextX1, n, ctx);
	BN_mod_inverse(Tx, k, n, ctx);
	BN_mod_mul(ctextY1, ctextY1, Tx, n, ctx);
	tmp = (uchar *)BN_bn2hex(ctextY1);
	strcpy_s((char *)signature.Y1, strlen((char *)tmp) + 1, (char *)tmp);
}

bool ECC::ecdsa_validation(Ciphertext & signature, uchar * plaintext)
{
	if (signature.Y0 == NULL || signature.Y1 == NULL || plaintext == NULL)
		return false;

	/* 读取Y0, Y1, Y2为大数 */
	BN_hex2bn(&ctextY0, (char *)(signature.Y0));
	BN_hex2bn(&ctextY1, (char *)(signature.Y1));
///	BN_hex2bn(&ctextY2, (char *)(signature->Y2));

	/* 读取明文为大数 */
	BN_bin2bn(plaintext, BN_num_bytes(n), ptextX1);

	/* 计算公钥 */
	Beta = EC_POINT_new(group);
	EC_POINT_mul(group, Beta, d, NULL, NULL, ctx);

	T = EC_POINT_new(group);
	/* 身份验证 */
	BN_mod_inverse(Tx, ctextY1, n, ctx);
	BN_mod_mul(Ty, ctextY0, Tx, n, ctx);
	BN_mod_mul(Tx, ptextX1, Tx, n, ctx);
	EC_POINT_mul(group, T, Tx, Beta, Ty, ctx);
	EC_POINT_get_affine_coordinates_GFp(group, T, Tx, Ty, ctx);
	
	if (BN_cmp(Tx, ctextY0) == 0)
		return true;

	return false;
}
