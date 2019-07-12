#ifndef HASH_H__
#define HASH_H__
#define _CRT_SECURE_NO_WARNINGS 
#pragma once
#include <iostream>
#include <openssl\sha.h>

/* This class creates a hash of a Document or string and encodes it in Base64URL
	in order for the result to be compatible for signing usinfg Azure Key Vault 
	*/
static const char base64_url_alphabet1[] = {

	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',

	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',

	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',

	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',

	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'

};

class Hash
{
public:
	//Hash constructor (string/document path, 
	Hash(const char* path, std::string , bool );
	std::string getHash();


private:
	char output_buffer[100];
	std::string output = "";
	unsigned char calc_hash[100];

	std::string base64_encoder1(const std::string &);
	std::string base64_decoder1(const std::string &);


	void hashDocument(const char *, std::string);
	void hashString(const char *, std::string);

	int calc_sha256(const char*);
	int calc_sha384(const char*);
	int calc_sha512(const char *);


	void SHA256hash(std::string);
	void SHA384hash(std::string);
	void SHA512hash(std::string);

	void to_base64URL(unsigned char hash[SHA512_DIGEST_LENGTH], int);
	std::string decodeURL(std::string line);
	void to_hex(unsigned char hash[SHA512_DIGEST_LENGTH], int);


};
#endif
