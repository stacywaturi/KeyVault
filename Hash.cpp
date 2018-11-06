#include "Hash.h"
#include <sstream>
#include <vector>
#include <iomanip>


std::string Hash::tohex(unsigned char s) {
	std::stringstream ss;
	ss << std::hex << (int)s;
	return ss.str();
}



std::string Hash::SHA256hash(std::string line) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, line.c_str(), line.length());
	SHA256_Final(hash, &sha256);

	std::stringstream ss;
	std::string output = "";

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << hash[i];
	}

	output = base64_encoder1(ss.str());
	return output;


}


std::string Hash::SHA384hash(std::string line) {
	unsigned char hash[SHA512_DIGEST_LENGTH];

	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	SHA384_Update(&sha384, line.c_str(), line.length());
	SHA384_Final(hash, &sha384);
	

	std::string output = "";
	std::stringstream ss;

	

	for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
	{
		ss << hash[i];
	}
	
	output = base64_encoder1(ss.str());
	return output;


}

std::string Hash::SHA512hash(std::string line) {
	unsigned char hash[SHA512_DIGEST_LENGTH];

	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, line.c_str(), line.length());
	SHA512_Final(hash, &sha512);
	

	std::string output = "";
	std::stringstream ss;

	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		ss << hash[i];
	}
	


	output = base64_encoder1(ss.str());

	return output;

}



std::string Hash::base64_encoder1(const std::string & in) {

	std::string out;

	int val = 0, valb = -6;

	size_t len = in.length();

	unsigned int i = 0;

	for (i = 0; i < len; i++) {

		unsigned char c = in[i];

		val = (val << 8) + c;

		valb += 8;

		while (valb >= 0) {

			out.push_back(base64_url_alphabet1[(val >> valb) & 0x3F]);

			valb -= 6;

		}

	}

	if (valb > -6) {

		out.push_back(base64_url_alphabet1[((val << 8) >> (valb + 8)) & 0x3F]);

	}

	return out;
}



std::string Hash:: base64_decoder1(const std::string & in) {

	std::string out;

	std::vector<int> T(256, -1);

	unsigned int i;

	for (i = 0; i < 64; i++) T[base64_url_alphabet1[i]] = i;



	int val = 0, valb = -8;

	for (i = 0; i < in.length(); i++) {

		unsigned char c = in[i];

		if (T[c] == -1) break;

		val = (val << 6) + T[c];

		valb += 6;

		if (valb >= 0) {

			out.push_back(char((val >> valb) & 0xFF));

			valb -= 8;

		}

	}

	return out;

}
std::string Hash::decodeURL(std::string line) {
	std::string output = "";

	output = base64_decoder1(line);
	return output;
}

