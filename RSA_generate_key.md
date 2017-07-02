# 生成RSA算法的公钥和私钥

命令行输入`openssl`打开`openssl.exe`

## 私钥生成
```
genrsa -out rsa_private_key.pem 1024
```

## 公钥生成
```
rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```