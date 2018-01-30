#pragma once

#define BASE64SUCC 0
#define BASE64FAIL 1

int	base64_encode(const char * bindata, char * base64, int binlength);
int	base64_decode(const char * base64, unsigned char * bindata);
void print_hex(char* buff);