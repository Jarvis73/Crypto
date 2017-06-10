#pragma once

#include <cstdio>
#include <cstring>
#include <openssl\rand.h>
#include <openssl\bn.h>
#include <openssl\ec.h>

typedef unsigned char uchar;
typedef unsigned int uint;

typedef struct tagECCInfo 
{
	char *a;
	char *b;
	char *p;
	char *n;
	char *Gx;
	char *Gy;
	char *d;
} ECCInfo;

typedef struct tagCiphertext
{
	uchar *r;
	uchar *s;
} Ciphertext;