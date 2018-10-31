#ifndef HASH_H__
#define HASH_H__
#pragma once
#include <iostream>
#include <openssl\sha.h>
//
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
	

	std::string tohex(unsigned char s);

	std::string SHA256hash(std::string line);
	std::string SHA384hash(std::string line);
	std::string SHA512hash(std::string line);
	std::string decodeURL(std::string line);

private:

	
	std::string base64_encoder1(const std::string &);
	std::string base64_decoder1(const std::string & in);

	

	
};
#endif
