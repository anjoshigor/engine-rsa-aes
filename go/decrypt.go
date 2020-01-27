package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
)

const privateRsaKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEArWUfFIWAl/1xgf80ebbv2dokGXM9eoi1v/tE/b2a42TiKYt1
7DeVkZtggXZ+VcCjHv4agy68Sq1vjgoMGpqBDQ4BtqMFpr6G35mzdMCsEN73QTq2
3l1ZIaSjBw04r5K/cclzi3XsHOoEBiZbKZN2xXAv878cP5tLuJWEE+Tm51SMeboK
eMENiYz3SrwPkcWvbcJXYyRSnWV0aTcAnujdpg9jEmfsukKbJXc+1aURMbgzBMBH
MwpCpa0MlxBMqiRs6DQFIviMlqwd1lMevWcMA0TEJguQJhuoA8fpQCcrLuKkLAlU
tWvTY9PujsH0SUdVA2FS/luzuB0GkVtHAxh2sQIDAQABAoIBAQCZzkoMdQOFTq4h
5tOQZ6JINwSwgpV1HNFDU0p2XXqH3JP00B0xBHkq6I1pKUeVH0RSmInB9XHWOBPt
BaKI8qYog1UnwWGg7/5JV1hk5wd6C519gex2QI1wl055UdQHgX9KGqzgdyCS4U3i
eqGAtqqzJfmTF+Gh1koLmKzIzNG5PcLKDs4KjcqMpdAIk5LVtzc9/5JgHAD8eyQY
Ph6GDB/vU3yH0WpI4J7BbhcuO/8eVphIsa41E9wvt+JmjhI4Twc3GG212pmr+QSW
JXOWK2/mNZqZ0EtQgxv6pOrZiRHyWT/vqTCZREBgvqZM/Qfr21PVNxUnfCqRtlou
f0Dm05mxAoGBAN/mbSFUygX6DmQgwHyHmt4aBEkZeAVjfp93FGclGhkdf045zs+K
+THoBkEV/gsJgwGwurvuNpv7rlu9+IInNLJ11DxASClx4Oex1aSl61ZV9VY4mYQd
q1Msx33XEc412w8f8yAR9sq7zznRCHUfNMU3Tr77TVkhM5+5vqptzEAFAoGBAMZB
Dw5T/y4pUFwHLFkPNHHAtnCvcxfEgMYOJWfb0D9XejV7A/J7FWVxnNTqiOs4+5OP
ZrdlGwVC/NzdjCId7YPtsUEA/C1NN3gvHJenyI3JFQhoRPhgL1krdedQtHdv6BBP
uhjHWjMC1e4FhV7fXxzNE7VSybe3CFny6aputde9AoGBAIDoRcR+8KFoSojTYn9Q
A5YEHJuJklRn6CsfgBuyfMgg936uQae0N6zIDXHDm7P3EfoTKi+xArfju4sOYNlu
gSSOOldGG0XhTr+W344gCNJ4QvwVMi2id1U33tNQ0+uJjkmy92NrdE9cuf5rnxbv
lI5HPYsvXGUIfJRleKTe+k2RAoGBAIgg0/26n1VK+Oq34jOkxRX2hU8KqbSAMQvN
WtHdlThpEHj4ZtVwvlhRkqaABFO/ZL8FkDoNKmiKfqYJWddzRUt5QmSoEH/qrVPQ
xYk8o/D3SYHkVrdVFC3eMa8LM19vb6EDnXy2JbExGUO+dr2WEvDrv8SZe/ixrQJW
USu9qQ7hAoGAdiTyV/HAJDy1HTnBqLYwjJKYPtMPmwczwfh0Y29Yv97M1KbECmZB
UNYELq50kpuxOqAfT0k6WaAkXvBFxUjRr1i4GkZ3Zm22lw8hDFQUw0cgyWXo0GON
I1U2OzajtlVbaUvU0a2zKo8j6GYaKIjnrE3utloj3JnS5DXdkDWCOF8=
-----END RSA PRIVATE KEY-----`

const keyReceivedFromDataHub = "rB5SLoEOpjCPLzOJ3xQ8osaYjR1txqGvIgS0uQLfI9QrvvwC3zg9zZTONZki6vVnLKlga0L+fbJPLQV30s5vQ+tkoIlmUNBOkliEJGTzA5ZdhiP7uMZQMvaEpu3psZUXad/cr8rlGg0KhaXwvYocjsaOsTrCjqATvR4v4/cgbxWKXVcj9lDOlUsMrjT5vnJO0VBYygHxZbNGKH3v83H4J1pZ7c9TX64n5EdMCjfxlPVsKxfo+me2FAFuNv2fhdVKFfCaw1thBbye2EG+NfPY75gOWBBelgE0kNmFCtCbCDHIw6MvHqOnDLqqaE5ULH1+3Y8zyvLVsARLkN7saVd/iQ=="
const messageFromWebhook = "wgXxtCHh9Q+E7Ez818arjg"

func main() {
	privateKey := BuildPrivateKey([]byte(privateRsaKey))

	if privateKey == nil {
		return
	}
	aesKeyByteArray, e := FetchPlainAesKey(privateKey, keyReceivedFromDataHub)

	if e != nil {
		fmt.Println(e)
		return
	}
	s, e := DecryptWithAES(aesKeyByteArray, messageFromWebhook)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println("Decrypted message: ", s)
}

func FetchPlainAesKey(privateRsaKey *rsa.PrivateKey, keyReceivedFromDataHub string) ([]byte, error) {
	decodeString, e := base64.StdEncoding.DecodeString(keyReceivedFromDataHub)
	if e != nil {
		fmt.Println(e)
		return nil, e
	}
	return DecryptWithPrivateKey(decodeString, privateRsaKey), nil
}

func BuildPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			fmt.Println(err)
			return nil
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return key
}

func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	byteSliceAesKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)

	if err != nil {
		fmt.Println(err)
	}
	return byteSliceAesKey
}

func DecryptWithAES(aesKey []byte, text string) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.StdEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	msg := decodedMsg

	cbc := cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize))
	cbc.CryptBlocks(msg, msg)

	unpadMsg, err := RemovePadding(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}

func RemovePadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}

	return value
}
