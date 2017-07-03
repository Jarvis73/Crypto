#pragma once

#include "resource.h"
#include "BaseClass.h"

/* 散列算法类 */
class MyHash : public Crypto
{
public:
	MyHash();
	~MyHash();
	void MyMD5(uchar *plaintext, uchar *hashcode);
	void MySha(uchar *plaintext, uchar *hashcode);
};

/* 散列算法测试 */
int MD5Test();
int ShaTest();
