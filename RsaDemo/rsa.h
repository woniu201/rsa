#pragma once

#define PUBLICKEY			0x10
#define PRIKEY				0x11
#define VERIFYSIGN_SUCC		0x12
#define VERIFYSIGN_FAIL		0x13


int public_encrypt(unsigned char*data, int data_len, const char*key, unsigned char*encrypted);
int private_decrypt(unsigned char*enc_data, int data_len, const char*key, unsigned char*decrypted);

unsigned char * getSign(char* keyFile, char* plainText, unsigned char* cipherText, unsigned int *cipherTextLen);
int verifySign(char* certFile, unsigned char* cipherText, unsigned int cipherTextLen, char* plainText);