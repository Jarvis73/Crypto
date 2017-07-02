# 密码学算法及其实现

## 零. 基类 -- **BaseClass**

```cpp
void dump_hex(unsigned char * src, int n, unsigned char * dest)     // 以16进制转储
void scan_hex(unsigned char * src, int n, unsigned char * dest)     // 以16进制读取
void new_prime_bn(BIGNUM *ret, int bits)                            // 生成一个大素数
void new_rand_bn(BIGNUM * ret, int bits)                            // 生成一个随机大数
void new_psudo_rand_bn(BIGNUM * ret, int bits)                      // 生成一个伪随机大数
```

## 一. 公钥密码

### 1. Menezes-Vanstone公钥密码体制 -- **Ecc**

* ECC -- 椭圆曲线加密算法
* ECDSA -- 签名/验证
* ECNR -- 签名/验证

```cpp
void init(ECCInfo *ei)          // 初始化椭圆曲线群
void free()                     // 释放内存
void dump_group()               // 显示椭圆曲线参数
void encrypt(uchar *plaintext, Ciphertext & ciphertext)             // ECC加密
void decrypt(Ciphertext & ciphertext, uchar *plaintext)             // ECC解密
void ecnr_signature(uchar *plaintext, Ciphertext & signature)       // ECNR数字签名
bool ecnr_validation(Ciphertext & signature, uchar *plaintext)      // ECNR身份验证
void ecdsa_signature(uchar *plaintext, Ciphertext & signature)      // ECDSA数字签名
bool ecdsa_validation(Ciphertext & signature, uchar *plaintext)     // ECDSA身份验证

int EccTest();                  // ECC算法测试
```

## 二. 分组密码


## 三. 散列算法 -- **MyHash**

* MD5
* SHA-1

```cpp
void MyMD5(uchar *plaintext, uchar *hashcode)       // 用MD5计算报文摘要

int MD5Test()       // MD5算法测试
```