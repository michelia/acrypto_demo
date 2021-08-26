# acrypto_demo

## rsa

### 生成证书
```
rsa key -> crypto/x509 -> encoding/pem ->string
key            编码           序列化(base64) 
```

### 读取密钥
```
string -> encoding/pem -> crypto/x509 ->rsa key
          反序列化          解码          key
```

## 代码
见[gen_read_key](rsa/gen_read_key.go)

## ecc

### 生成证书
```
ecc key -> crypto/x509 -> encoding/pem ->string
key            编码           序列化(base64)
```


### 读取密钥
```
string -> encoding/pem -> crypto/x509 ->ecc key
            反序列化        解码          key
```

## 代码
见[gen_read_key](ecc/gen_read_key.go)

# 参考
- https://www.sohamkamani.com/golang/rsa-encryption/

