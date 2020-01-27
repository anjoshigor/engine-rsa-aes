# Decription Code Samples

## GoLang

Install the Go language through its website, then run:

```console
go version
```

This should prompt something like that

```console
go version go1.13.6 windows/amd64
```

Now go to the directory `go/` and run

```console
go run decrypt.go
```

## NodeJS

```console
npm install
```

```console
node decrypt.js
```

## Java

```
mvn package
```

```
java -Dfile.encoding=UTF-8 -classpath .\target\classes App
```

#### How to generate the keys using openssl

- **1ª Generates the private key**

```console
openssl genrsa -out chave_rsa.pem 2048
```

- **2ª Generates the public key**

```console
openssl rsa -pubout -in chave_rsa.pem -out chave_publica.key
```

- **3ª Generate the key with BEGIN PRIVATE KEY pto use on the project**

```console
openssl pkcs8 -topk8 -inform PEM -in chave_rsa.pem -out chave_privada.pem -nocrypt
```
