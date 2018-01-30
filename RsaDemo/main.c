/********************************************************
Copyright (C), 2016-2017,
FileName: 	main
Author: 	woniu201
Email: 		wangpengfei.201@163.com
Created: 	2018/01/30
Description:RSA算法demo
********************************************************/

#include <stdio.h>
#include "rsa.h"
#include "base64.h"

int main()
{
	char* pri = "pri";
	char* pub = "pub";

	char plainText[] = "8f8c733bf4ab4a039d85d7d1d470759b";
	printf("plainText: %s\n\n", plainText);

	unsigned char cipherText[1024 * 4] = {0};
	unsigned int  cipherTextLen  = 0;
	unsigned char cipherTextBase64[1024 * 4] = {0};
	unsigned char encrpty[1024] = { 0 };
	unsigned char decrpty[1024] = { 0 };

	printf("========================= sign and verify ======================\n");
	if (NULL == getSign(pri, plainText, cipherText, &cipherTextLen))
	{
		printf("sign fail！\n");
		return -1;
	}
	else
	{
		printf("sign  hex:\n");
		print_hex(cipherText);
		base64_encode(cipherText, cipherTextBase64, strlen(cipherText));
		printf("sign base64:\n%s\n", cipherTextBase64);
	}

	if (verifySign(pub, cipherText, cipherTextLen, plainText) == VERIFYSIGN_SUCC)
	{
		printf("Signature Verified Ok.\n");
	}
	else
	{
		printf("verifySign fail！\n");
		return -2;
	}
	

	printf("\n");
	printf("\n");
	printf("========================= encrypt and decrypt ======================\n");
	int encrypted_length = public_encrypt(plainText, strlen(plainText), pub, encrpty);
	if (encrypted_length == -1)
	{
		printf("encrypt error \n");
		return -3;
	}
	else
	{
		printf("encrypt hex:\n");
		print_hex(encrpty);
		memset(cipherTextBase64,  0, strlen(cipherTextBase64));
		base64_encode(encrpty, cipherTextBase64, strlen(encrpty));
		printf("sign base64:\n%s\n", cipherTextBase64);

		int decrpted_length = private_decrypt(encrpty, encrypted_length, pri, decrpty);
		if (decrpted_length == -1)
		{
			printf("decrypt fail \n");
			return -4;
		}
		else
		{
			printf("decrypt: %s\n", decrpty);
		}
	}
	return 0;
}