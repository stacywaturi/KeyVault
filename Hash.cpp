#include "Hash.h"
#include <sstream>
#include <vector>
#include <iomanip>

Hash::Hash(const char* path, std::string algorithm, bool is_doc) {
	//Switch flag (is_doc)?
	switch (is_doc)
	{
	case 1:
		hashDocument(path, algorithm);		//Hash with first arg as file path 
		break;
	case 0:
		hashString(path, algorithm);		//Hash with first arg as string
		break;

	default:
		hashString(path, algorithm);
		break;
	}

}
//Return Hashed String
std::string Hash::getHash() {

	return output;
}

/*Call to HASH DOCUMENT
The path defines the location of the file
The algorithm defines the algorithm used to hash the file*/
void Hash::hashDocument(const char* path, std::string algorithm) {
	int length = 0;
	if (algorithm == "RS256" || algorithm == "ES256") {
		calc_sha256(path);
		length = SHA256_DIGEST_LENGTH;

	}

	else if (algorithm == "RS384" || algorithm == "ES384") {
		std::cout << "RS384" << std::endl;
		calc_sha384(path);
		length = SHA384_DIGEST_LENGTH;
	}

	else if (algorithm == "RS512" || algorithm == "ES512") {
		std::cout << "RS512" << std::endl;
		calc_sha512(path);
		length = SHA512_DIGEST_LENGTH;
	}
	else {
		std::cout << "INVALID ALGORITHM" << std::endl;
	}

	to_base64URL(calc_hash, length);

}
/*Call to HASH STRING
The path defines the string to be hashed
The algorithm defines the algorithm used to hash the string*/
void Hash::hashString(const char* string, std::string algorithm) {

	int length = 0;
	if (algorithm == "RS256" || algorithm == "ES256") {
		SHA256hash(string);
		length = SHA256_DIGEST_LENGTH;

	}

	else if (algorithm == "RS384" || algorithm == "ES384") {
		std::cout << "RS384" << std::endl;
		SHA384hash(string);
		length = SHA384_DIGEST_LENGTH;
	}

	else if (algorithm == "RS512" || algorithm == "ES512") {
		std::cout << "RS512" << std::endl;
		SHA512hash(string);
		length = SHA512_DIGEST_LENGTH;
	}
	else {
		std::cout << "INVALID ALGORITHM" << std::endl;
	}


	to_base64URL(calc_hash, length);

	//to_hex(calc_hash, length);

}
/*-----------HASH ALGORITHMS-----------------*/
/*Calculate checksum of file using SHA256
*/
int Hash::calc_sha256(const char* path)
{

	FILE* file = fopen(path, "rb");
	if (!file) return -1;

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	const int bufSize = 32768;
	char* buffer = (char*)malloc(bufSize);
	int bytesRead = 0;
	if (!buffer) return -1;
	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead);
	}
	SHA256_Final(calc_hash, &sha256);

	fclose(file);
	free(buffer);

	return 0;
}
/*Calculate checksum of file using SHA384
*/
int Hash::calc_sha384(const char* path)
{

	FILE* file = fopen(path, "rb");
	if (!file) return -1;

	std::cout << "calc_sha384" << std::endl;
	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	const int bufSize = 32768;
	char* buffer = (char*)malloc(bufSize);
	int bytesRead = 0;
	if (!buffer)
		return -1;
	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA384_Update(&sha384, buffer, bytesRead);
	}
	SHA384_Final(calc_hash, &sha384);

	fclose(file);
	free(buffer);

	return 0;
}
/*Calculate checksum of file using SHA512
*/
int Hash::calc_sha512(const char* path)
{
	FILE* file = fopen(path, "rb");
	if (!file) return -1;

	std::cout << "calc_sha512" << std::endl;
	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	const int bufSize = 32768;
	char* buffer = (char*)malloc(bufSize);
	int bytesRead = 0;
	if (!buffer)
		return -1;
	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA512_Update(&sha512, buffer, bytesRead);
	}
	SHA512_Final(calc_hash, &sha512);

	fclose(file);
	free(buffer);

	return 0;
}

/*Generate Hash of string using SHA256
*/
void Hash::SHA256hash(std::string line) {
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, line.c_str(), line.length());
	SHA256_Final(calc_hash, &sha256);

}
/*Generate Hash of string using SHA384
*/
void Hash::SHA384hash(std::string line) {
	SHA512_CTX sha384;
	SHA384_Init(&sha384);
	SHA384_Update(&sha384, line.c_str(), line.length());
	SHA384_Final(calc_hash, &sha384);
}
/*Generate Hash of string using SHA512
*/
void Hash::SHA512hash(std::string line) {
	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, line.c_str(), line.length());
	SHA512_Final(calc_hash, &sha512);
}

/*-----------------------------------------------------------------------------*/
/*Convert Hash to Base64URL */
void Hash::to_base64URL(unsigned char hash[SHA512_DIGEST_LENGTH], int length)
{

	std::stringstream ss;

	for (int i = 0; i < length; i++)
	{
		ss << hash[i];
	}

	output = base64_encoder1(ss.str());
}
/*Decode from Base64URL */
std::string Hash::decodeURL(std::string line) {
	std::string output = "";

	output = base64_decoder1(line);
	return output;
}
/*Convert Hash to HEX format */
void Hash::to_hex(unsigned char hash[SHA512_DIGEST_LENGTH], int length)
{


	for (int i = 0; i < length; i++)
	{
		sprintf(output_buffer + (i * 2), "%02x", hash[i]);
	}

	output = output_buffer;
	//output_buffer[] = 0;

}


/*-----------BASE64URL ALGORITHMS-----------------*/
/*BASE64URL ENCODER*/
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


/*BASE64URL DECODER*/
std::string Hash::base64_decoder1(const std::string & in) {

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

