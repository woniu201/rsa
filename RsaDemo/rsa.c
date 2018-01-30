/********************************************************
Copyright (C), 2016-2017,
FileName: 	rsa
Author: 	woniu201
Email: 		wangpengfei.201@163.com
Created: 	2018/01/30
Description:实现RSA的签名验签，加密解密
********************************************************/

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "rsa.h"

#pragma comment(lib, "libeay32.lib")   
#pragma comment(lib, "ssleay32.lib")   

int padding = RSA_SSLV23_PADDING;

/************************************
@ Brief:		读取PEM文件的私钥
@ Author:		woniu201 
@ Created: 		2018/01/30
@ Return:		结构体指针EVP_PKEY    
************************************/
EVP_PKEY *open_private_key(const char *keyfile) 
{
	EVP_PKEY *key = NULL;
	RSA *rsa = RSA_new();

	OpenSSL_add_all_algorithms();
	BIO *bp = BIO_new_file(keyfile, "rb");
	if (NULL == bp) {
		printf("open_private_key bio file new error!");
		return NULL;
	}

	rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, NULL);
	if (rsa == NULL) {
		printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
		BIO_free(bp);
		RSA_free(rsa);
		return NULL;
	}

	//printf("open_private_key success to PEM_read_bio_RSAPrivateKey!\n");
	key = EVP_PKEY_new();
	if (NULL == key) {
		printf("open_private_key EVP_PKEY_new failed\n");
		RSA_free(rsa);
		return NULL;
	}

	EVP_PKEY_assign_RSA(key, rsa);
	return key;
}

/************************************
@ Brief:		读取PEM文件的公钥
@ Author:		woniu201
@ Created: 		2018/01/30
@ Return:		结构体指针EVP_PKEY
************************************/
EVP_PKEY *open_public_key(const char *keyfile) {
	EVP_PKEY *key = NULL;
	RSA *rsa = RSA_new();

	OpenSSL_add_all_algorithms();
	BIO *bp = BIO_new_file(keyfile, "rb");
	if (NULL == bp) {
		printf("open_private_key bio file new error!");
		return NULL;
	}

	rsa = PEM_read_bio_RSA_PUBKEY(bp, &rsa, NULL, NULL);
	if (rsa == NULL) {
		printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
		BIO_free(bp);
		RSA_free(rsa);
		return NULL;
	}

	//printf("open_private_key success to PEM_read_bio_RSAPrivateKey!\n");
	key = EVP_PKEY_new();
	if (NULL == key) {
		printf("open_private_key EVP_PKEY_new failed\n");
		RSA_free(rsa);
		return NULL;
	}

	EVP_PKEY_assign_RSA(key, rsa);
	return key;
}

/************************************
@ Brief:		读取PEM创建RSA结构体 
@ Author:		woniu201
@ Created: 		2018/01/30
@ Return:		结构体指针RSA
************************************/
RSA* createRSA(const  char*key, int flag)
{
	RSA *rsa = RSA_new();
	OpenSSL_add_all_algorithms();
	BIO *keybio = BIO_new_file(key, "rb");
	if (NULL == keybio) {
		printf("open_private_key bio file new error!");
		return NULL;
	}

	if (flag == PUBLICKEY)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
		if (rsa == NULL) {
			printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
			BIO_free(keybio);
			RSA_free(rsa);
			return NULL;
		}
	}
	else if(flag == PRIKEY)
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
		if (rsa == NULL) {
			printf("open_private_key failed to PEM_read_bio_RSAPrivateKey!\n");
			BIO_free(keybio);
			RSA_free(rsa);
			return NULL;
		}
	}
	else
	{
		return NULL;
	}
	return rsa;
}

/************************************
@ Brief:		公钥加密
@ Author:		woniu201
@ Created: 		2018/01/30
@ Return:		密文长度
************************************/
int public_encrypt(unsigned char*data, int data_len, const char*key, unsigned char*encrypted)
{
	RSA* rsa = createRSA(key, PUBLICKEY); 
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_PADDING);
	return result;
}

/************************************
@ Brief:		私钥解密
@ Author:		woniu201
@ Created: 		2018/01/30
@ Return:		明文长度 
************************************/
int private_decrypt(unsigned char*enc_data, int data_len, const char*key, unsigned char*decrypted)
{
	RSA* rsa = createRSA(key, PRIKEY);
	int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_SSLV23_PADDING);//RSA_SSLV23_PADDING
	return result;
}

/************************************
@ Brief:		签名
@ Author:		woniu201
@ Created: 		2018/01/30
@ Return:		
************************************/
unsigned char * getSign(char* keyFile, char* plainText, unsigned char* cipherText, unsigned int *cipherTextLen)
{
// 	FILE* fp = fopen(keyFile, "r");
// 	if (fp == NULL)
// 		return NULL;
// 
// 	/* Read private key */
// 	EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
// 	fclose(fp);

	EVP_PKEY* pkey = open_private_key(keyFile);
	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	/* Do the signature */
	EVP_MD_CTX     md_ctx;
	//EVP_SignInit(&md_ctx, EVP_sha1());
	EVP_SignInit(&md_ctx, EVP_md5());
	EVP_SignUpdate(&md_ctx, plainText, strlen(plainText));
	int err = EVP_SignFinal(&md_ctx, cipherText, cipherTextLen, pkey);
	if (err != 1) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	EVP_PKEY_free(pkey);

	return cipherText;
}

/************************************
@ Brief:		验签
@ Author:		woniu201
@ Created: 		2018/01/30
@ Return:		
************************************/
int verifySign(char* certFile, unsigned char* cipherText, unsigned int cipherTextLen, char* plainText)
{
// 	/* Get X509 */
// 	FILE* fp = fopen(certFile, "r");
// 	if (fp == NULL)
// 		return -1;
// 	X509* x509 = PEM_read_X509(fp, NULL, NULL, NULL);
// 	fclose(fp);
// 
// 	if (x509 == NULL) {
// 		ERR_print_errors_fp(stderr);
// 		return -1;
// 	}
// 
// 	/* Get public key - eay */
// 	EVP_PKEY *pkey = X509_get_pubkey(x509);
// 	if (pkey == NULL) {
// 		ERR_print_errors_fp(stderr);
// 		return -1;
// 	}
// 	fclose(fp);

	EVP_PKEY* pkey = open_public_key(certFile);
	if (pkey == NULL)
	{
		return VERIFYSIGN_FAIL;
	}

	/* Verify the signature */
	EVP_MD_CTX md_ctx;
	EVP_VerifyInit(&md_ctx, EVP_md5());
	EVP_VerifyUpdate(&md_ctx, plainText, strlen((char*)plainText));
	int err = EVP_VerifyFinal(&md_ctx, cipherText, cipherTextLen, pkey);
	if (err != 1) {
		ERR_print_errors_fp(stderr);
		return VERIFYSIGN_FAIL;
	}
	EVP_PKEY_free(pkey);

	return VERIFYSIGN_SUCC;
}