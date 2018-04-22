# AES_128_breaker

This code implements a Square attack on 3 and a half rounds of AES.

Compile with :

```shell
    gcc -o aes-attack aes-128_enc.c
```
Then execute :

```shell
    ./aes-attack
```
    
In order to test it with a different key, you have to change the hardcoded key with the key you want to test.
