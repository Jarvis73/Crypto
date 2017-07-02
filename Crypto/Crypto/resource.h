#pragma once

#include <cstdio>
#include <cstring>
#include <openssl\rand.h>
#include <openssl\bn.h>
#include <openssl\ec.h>
#include <openssl\md5.h>

typedef unsigned char uchar;
typedef unsigned int uint;

/* ����ECC����Բ���߽ṹ */
typedef struct tagECCInfo 
{
	char *p;
	char *a;
	char *b;
	char *Gx;
	char *Gy;
	char *n;
	char *d;
} ECCInfo;

/* ����ECC�����Ľṹ */
typedef struct tagCiphertext
{
	uchar *r;
	uchar *s;
} Ciphertext;

