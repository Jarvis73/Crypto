#pragma once

#include "resource.h"
#include "BaseClass.h"

/* ɢ���㷨�� */
class MyHash : public Crypto
{
public:
	MyHash();
	~MyHash();
	void MyMD5(uchar *plaintext, uchar *hashcode);
	void MySha(uchar *plaintext, uchar *hashcode);
};

/* ɢ���㷨���� */
int MD5Test();
int ShaTest();
