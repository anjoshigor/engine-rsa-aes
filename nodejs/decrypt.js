const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const AES_256_CBC = 'aes-256-cbc';

const aesKey = 'rB5SLoEOpjCPLzOJ3xQ8osaYjR1txqGvIgS0uQLfI9QrvvwC3zg9zZTONZki6vVnLKlga0L+fbJPLQV30s5vQ+tkoIlmUNBOkliEJGTzA5ZdhiP7uMZQMvaEpu3psZUXad/cr8rlGg0KhaXwvYocjsaOsTrCjqATvR4v4/cgbxWKXVcj9lDOlUsMrjT5vnJO0VBYygHxZbNGKH3v83H4J1pZ7c9TX64n5EdMCjfxlPVsKxfo+me2FAFuNv2fhdVKFfCaw1thBbye2EG+NfPY75gOWBBelgE0kNmFCtCbCDHIw6MvHqOnDLqqaE5ULH1+3Y8zyvLVsARLkN7saVd/iQ==';
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
-----END RSA PRIVATE KEY-----`;
let message = '6x+DLqdIokSyqOfuYpRATds24dZNfd3RfZm3DNuGmMJTQt0a3AwNMHYr7oBuGS8uTzxWKOuKgj+fO/QJk0VeuWgKVboEIQuwRbWF9YK8k51XaN5vH96ZJlcmd5zHhw+0jAWKntLYR2zDPxaMHFqr60hh/EZgAdnAfp15U6/sv+J27JadKFFKLldCRVZ087iEJxL35qNCx5qvzBNE9/LQwkjdP1viofrO2W/KYd+U4/sy7c+/UMT5q3MAvKruVuN+y6lrA3Gmm8NHey27DZj+ZvFHKcuYhTbp69D9ZRM7WiWABc7ax1h1UaTsoFs2t9GlaS50+3QuwhUNRVj+mU7oPJBQ9xKzvtK3QOqXyUuUopZ8m/Y7NJ6S6kfGO5uK5vvzFwLkSHm/0sE7BJnSw/12g3N7UyYdYmg+qwwjUsbUCpcSr804d/iE64nbOQ/EP8sYLJlQvfM5AdvbOrYqJi51U1yrLIi1ImgaS/1Ue69dzS6TWiIGdvrJ1hhAV6DirQIlhvJOuDNwMsM4H3Ol11B6spJDEuwFLYhbzsftoOEoacR/GW0hAe2sJfwxC4eqA9Dgy20ql+P7DCqeEg2WCqTCIY5bTj/6zUVZGVOUrD5p99m1hkYMref/tLoP1/zNfBYvCrm5cfxIvb8wNLyoQ24OcPXVkfOVE/WW09m2XJOTaTcw0fLjkI4GuMTaRg6Ririql/gAzLsPZKLcEd8bZJqPA4In+KQGeCaxfeQlFK1pHSj0gzc67G5cbnKIlA58LcZPw/0mKVbnkttTj5zrKtrTWz0r7ZxYj1XStx47oCZSGL1MyRgEobIKVHImwPI7Y+cm5oGoGM8o1GGQY3r1Kh1sehfcZbT4QiS+tpZu8ckSovnYpejW2D/ehF8oEUcH8A6Gn0va6B1FQx3hWT1JSKCS05iOtMz/EHawWJ0BskpbD3vfqQIQAdLrUAGBfdbiIVuBCz/4W++ao7zgifOBTlhic8maOOlS/2TYOLpPVTd9+o+6fqW79GbFgYE4Z4nJmxIg/v1VzSkCsen7L/f976v6tQ';




const decryptMessage = (message, rsaPrivateKey, aesWebHookKey) => {
    //Decrypting aesWebHookKey using the RSA private key
    const rsa = new NodeRSA(rsaPrivateKey);
    rsa.setOptions({encryptionScheme: 'pkcs1'});
    const key = rsa.decrypt(aesWebHookKey, 'base64');

    //Adding padding if message is not multiple of 4
    message = addPadding(message);

    //Converting everything to buffer
    const bufferIV = Buffer.alloc(16);
    const bufferMessage = Buffer.from(message, 'base64');
    const bufferKey = Buffer.from(key, 'base64')
    
    //Decipher object
    const Decipher = crypto.createDecipheriv(AES_256_CBC, bufferKey, bufferIV);
    let decryptedMessage = Decipher.update(bufferMessage, 'base64');
    decryptedMessage = Buffer.concat([decryptedMessage, Decipher.final()]);
    return decryptedMessage.toString();
}

const addPadding = (text) => {
  const m = (text.length) % 4;
  if (m != 0){
    text += "=".repeat(4-m);
  }
  return text;
}

console.log(decryptMessage(message, privateRsaKey, aesKey))