#define _CRT_SECURE_NO_WARNINGS 
#include <conio.h>
#include "KeyVault.h"
#include "Hash.h"


#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif

 //globals
//Native Client APP
utility::string_t clientId = _XPLATSTR("9d98c3f3-78fa-4449-ae07-6a01f58a8446");

utility::string_t keyVaultName = _XPLATSTR("tf-test-vault");


bool verbose = false;
void create_key(KeyVault);
void get_all_keys(KeyVault );
void get_key(KeyVault );

void sign(KeyVault );
void create_cert(KeyVault );
void get_csr(KeyVault);
void merge_cert(KeyVault);


//////////////////////////////////////////////////////////////////////////////
//
#ifdef _WIN32
int wmain(int argc, wchar_t* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	std::wcout << _XPLATSTR("Enter Key vault name	:");
	std::wcout << keyVaultName << std::endl;
	//std::wcin >> keyVaultName;

	std::wcout << _XPLATSTR("Enter Client ID of Registered App	:");
	std::wcout << clientId.c_str() << std::endl;

	///////////////////////////////////////////////////////////////////////////
	//// Authenticate with Azure AD
	//////////////////////////////////////////////////////////////////////////

	KeyVault kvc;

	int AuthResponse = kvc.GetAuthenticateKeyVaultResponse(keyVaultName);
	std::wcout << AuthResponse << std::endl;

	int ClientCodeResponse = kvc.GetClientAuthCodeResponse(clientId);
	std::wcout << _XPLATSTR("CleientCodeRespocnse	:") << ClientCodeResponse << std::endl;

	/*int DeviceCodeResponse = kvc.GetDeviceCodeResponse(clientId);
	std::wcout << _XPLATSTR("DeviceCodeResponse	:") << DeviceCodeResponse << std::endl;

	int AuthenticateResponse = kvc.GetAuthenticateResponse(clientId);
	std::wcout << _XPLATSTR("AuthenticateResponse	:") << AuthenticateResponse << std::endl;*/

	utility::string_t  accessToken = _XPLATSTR("");
	utility::string_t tokenType = _XPLATSTR("");

	kvc.GetAccessToken(clientId, accessToken, tokenType);
	
	std::wcout << _XPLATSTR("Access token  : ") << accessToken << std::endl;
	std::wcout << _XPLATSTR("Token type  : ") << tokenType << std::endl;

	std::wcout << _XPLATSTR("Authenticating for KeyVault:") << keyVaultName.c_str() << _XPLATSTR("...") << std::endl;
	std::wcout << _XPLATSTR("clientId : ") << clientId.c_str() << _XPLATSTR("..") << std::endl;

	///////////////////////////////////////////////////////////////////////////
	//// Key Vault Action 
	//////////////////////////////////////////////////////////////////////////
	
	char type = 'y';
	char action;

	while (type == 'y' || type == 'Y') {
		//system("cls");
		std::cout << "Input Action eg. create key, list keys etc" << std::endl;
		std::cout << "1. Create Key" << std::endl
			<< "2. Get Specific Key" << std::endl
			<< "3. Get All Keys" << std::endl
			<< "4. Sign  " << std::endl
			<< "5. Create Certificate" << std::endl
			<< "6. Get CSR" << std::endl 
			<< "7. Merge cert" << std::endl
			<< "Enter option: ";

		std::cin >> action;
		switch (action) {
		case '1':
			create_key(kvc);
			break;
		case '2':
			get_key(kvc);
			break;

		case '3':
			get_all_keys(kvc);
			break;

		case '4':
			sign(kvc);
			break;

		case '5':
			create_cert(kvc);
			break;

		case '6':
			get_csr(kvc);
			break;

		case '7':
			merge_cert(kvc);
			break;

		default:
			std::cout << "Invalid menu option\n";
			break;
		}

		std::cout << "Continue? [y/n]: ";
		std::cin >> type;


	}
	system("pause");
	return 0;
}

void create_key(KeyVault kvc) {
	
	std::wcout << _XPLATSTR("Enter key name,type and size ") << std::endl;
	std::wcout << _XPLATSTR("keyname3 RSA 2048") << std::endl;
	utility::string_t keyname = _XPLATSTR("keyname3");
	utility::string_t keytype = _XPLATSTR("RSA");
	utility::string_t keysize = _XPLATSTR("2048");
	std::wcout << _XPLATSTR("Creating key ") << std::endl;
	bool rc = kvc.createdKey(keyname, keytype, keysize);

	if (rc == false) {
		std::wcout << _XPLATSTR("Cannot create key") << std::endl;
		return;
	}

	else
		std::wcout << _XPLATSTR("Key created") << std::endl;


}

void get_key(KeyVault kvc) {
	std::wcout << _XPLATSTR("Enter key name") << std::endl;

	utility::string_t keyname = _XPLATSTR("");

	std::wcin >> keyname;

	std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << keyname << _XPLATSTR("...") << std::endl;
	web::json::value jsonKey;
	bool rc = kvc.GetKeyValue(keyname, jsonKey);

	if (rc == false) {
		std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
		return;
	}

	std::wcout << _XPLATSTR("Key   : ") << (jsonKey[_XPLATSTR("key")]) << std::endl;

}

void get_all_keys(KeyVault kvc) {
	std::wcout << _XPLATSTR(" Querying KeyVault for all Keys  ") << std::endl;
	web::json::value jsonKey;
	utility::string_t action = _XPLATSTR("");
	bool rc = kvc.GetKeyValue(action, jsonKey);

	if (rc == false) {
		std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
		return;
	}
	std::wcout << _XPLATSTR("Keys  : ") << jsonKey << std::endl;

}


void sign(KeyVault kvc) {
	std::wcout << _XPLATSTR("Enter key name, algorithm and string") << std::endl;
	std::wcout << _XPLATSTR("keyname1 RS512 string1") << std::endl;
	utility::string_t keyname = _XPLATSTR("keyname1");

	std::string string1 = "hello world";
	utility::string_t algorithm = _XPLATSTR("ES384");
	std::string hashed = "";

	Hash hashObj;

	if (algorithm == _XPLATSTR("RS256") || algorithm == _XPLATSTR("ES256")) {
		hashed = hashObj.SHA256hash(string1).c_str();
		std::wcout << hashObj.SHA256hash(string1).c_str() << std::endl;
	}
	else if (algorithm == _XPLATSTR("RS384") || algorithm == _XPLATSTR("ES384")) {
		hashed = hashObj.SHA384hash(string1).c_str();
		std::wcout << hashObj.SHA384hash(string1).c_str() << std::endl;
	}
	else if (algorithm == _XPLATSTR("RS512") || algorithm == _XPLATSTR("ES512")) {
		hashed = hashObj.SHA512hash(string1).c_str();
		std::wcout << _XPLATSTR("Digest	:") << hashObj.SHA512hash(string1).c_str() << std::endl;
	}
	else
		std::wcout << _XPLATSTR("NOT A VALID ALGORITHM") << std::endl;

	//	std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << keyname.c_str() << _XPLATSTR("...") << std::endl; 
	web::json::value jsonKey;
	bool rc = kvc.GetKeyValue(keyname, jsonKey);

	if (rc == false) {
		std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
		return;
	}
	utility::string_t kid = (jsonKey[_XPLATSTR("key")])[_XPLATSTR("kid")].as_string();


	web::json::value jsonSignature;
	utility::string_t hash = utility::conversions::to_string_t(hashed);
	//	std::wcout << hash.length() << std::endl;

	bool rc2 = kvc.GetSignature(kid, algorithm, hash, jsonSignature);

	if (rc2 == false) {
		std::wcout << _XPLATSTR("Cant sign") << std::endl;
		return;
	}

	utility::string_t signValue = (jsonSignature[_XPLATSTR("value")]).as_string();
	std::wcout << _XPLATSTR("Signature  : ") << signValue << std::endl;

	std::wcout << _XPLATSTR("Decoding digest...") << std::endl;

	std::string unhashed = "";
	unhashed = hashObj.decodeURL(hashed);
	std::wcout << _XPLATSTR("Decoded digest:	") << unhashed.c_str() << std::endl;

	web::json::value jsonVerification;

	bool rc3 = kvc.GetVerification(kid, algorithm, hash, signValue, jsonVerification);
	if (rc3 == false) {
		std::wcout << _XPLATSTR("Cant verify") << std::endl;
		return;
	}

	std::wcout << _XPLATSTR("Verification  : ") << jsonVerification << std::endl;
}

void create_cert(KeyVault kvc) {

	std::wcout << _XPLATSTR(" Creating Certificate  ") << std::endl;


	bool rc = kvc.createdCert();

	if (rc == false) {
		std::wcout << _XPLATSTR("Certificate not created") << std::endl;
		return;
	}



	
}

void get_csr(KeyVault kvc) {

	std::wcout << _XPLATSTR(" Retrieving CSR  ") << std::endl;

	web::json::value jsonKey;
	utility::string_t action = _XPLATSTR("myCert11");
	
	bool rc = kvc.getCSRResponse(action, jsonKey);

	if (rc == false) {
		std::wcout << _XPLATSTR("Certificate not found") << std::endl;
		return;
	}

	std::wcout << _XPLATSTR("CSR   : ") << (jsonKey[_XPLATSTR("csr")]) << std::endl;

	utility::string_t CSR = _XPLATSTR("-----BEGIN CERTIFICATE REQUEST-----\n") + (jsonKey[_XPLATSTR("csr")]).as_string()
							+ _XPLATSTR("\n-----END CERTIFICATE REQUEST-----");

	std::wcout << _XPLATSTR("CSR  edited : ") << CSR << std::endl;

	utility::ofstream_t out("myCSR1.csr");
	out << CSR;
	out.close();


}

void merge_cert(KeyVault kvc) {

	bool rc = kvc.mergedCert();

	if (rc == false) {
		std::wcout << _XPLATSTR("Certificate not merged") << std::endl;
		return;
	}

}






	
//	
//
//	std::wcin >> type >> action;
//
//	/////////////////////////////////////////////////////////////////////////////
//	////// Get Azure KeyVault secret
//	if (type == _XPLATSTR("key"))
//	{
//		if (action == _XPLATSTR("create")) {
//			std::wcout << _XPLATSTR("Enter key name,type and size ") << std::endl;
//			std::wcout << _XPLATSTR("keyname3 RSA 2048") << std::endl;
//			utility::string_t keyname = _XPLATSTR("keyname3");
//			utility::string_t keytype = _XPLATSTR("RSA");
//			utility::string_t keysize = _XPLATSTR("2048");
//			std::wcout << _XPLATSTR("Creating key ") << std::endl;
//			bool rc =  kvc.createdKey(keyname, keytype, keysize);
//
//			if (rc == false) {
//				std::wcout << _XPLATSTR("Cannot create key") << std::endl;
//				return 1;
//			}
//
//			else 
//				std::wcout << _XPLATSTR("Key created") << std::endl;
//
//			
//		}
//		else if (action == _XPLATSTR("all")) {
//			std::wcout << _XPLATSTR(" Querying KeyVault for all Keys  ") << std::endl;
//			web::json::value jsonKey;
//			action = _XPLATSTR("");
//			bool rc = kvc.GetKeyValue(action, jsonKey);
//
//			if (rc == false) {
//				std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
//				return 1;
//			}
//			std::wcout << _XPLATSTR("Keys  : ") << jsonKey << std::endl;
//		}
//
//		else if (action == _XPLATSTR("sign")) {
//			std::wcout << _XPLATSTR("Enter key name, algorithm and string") << std::endl;
//			std::wcout << _XPLATSTR("keyname1 RS512 string1") << std::endl;
//			utility::string_t keyname = _XPLATSTR("keyname1");
//			
//			std::string string1 = "string1";
//			utility::string_t algorithm = _XPLATSTR("RS512");
//			std::string hashed = "";
//
//			Hash hashObj;
//
//			if (algorithm == _XPLATSTR("RS256") || algorithm == _XPLATSTR("ES256")) {
//				hashed = hashObj.SHA256hash(string1).c_str();
//				std::wcout << hashObj.SHA256hash(string1).c_str() << std::endl;
//			}
//			else if (algorithm == _XPLATSTR("RS384") || algorithm == _XPLATSTR("ES384")) {
//				hashed = hashObj.SHA384hash(string1).c_str();
//				std::wcout << hashObj.SHA384hash(string1).c_str() << std::endl;
//			}
//			else if (algorithm == _XPLATSTR("RS512") || algorithm == _XPLATSTR("ES512")) {
//				hashed = hashObj.SHA512hash(string1).c_str();
//				std::wcout << _XPLATSTR("Digest	:") <<  hashObj.SHA512hash(string1).c_str() << std::endl;
//			}
//			else
//				std::wcout << _XPLATSTR("NOT A VALID ALGORITHM") << std::endl;
//
//		//	std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << keyname.c_str() << _XPLATSTR("...") << std::endl; 
//			web::json::value jsonKey;
//			bool rc = kvc.GetKeyValue(keyname, jsonKey);
//
//			if (rc == false) {
//				std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
//				return 1;
//			}
//			utility::string_t kid = (jsonKey[_XPLATSTR("key")])[_XPLATSTR("kid")].as_string();
//
//
//			web::json::value jsonSignature;
//			utility::string_t hash = utility::conversions::to_string_t(hashed);
//		//	std::wcout << hash.length() << std::endl;
//
//			bool rc2 = kvc.GetSignature(kid, algorithm, hash, jsonSignature);
//
//			if (rc2 == false) {
//				std::wcout << _XPLATSTR("Cant sign") << std::endl;
//				return 1;
//			}
//
//			utility::string_t signValue = (jsonSignature[_XPLATSTR("value")]).as_string();
//			std::wcout << _XPLATSTR("Signature  : ") << signValue << std::endl;
//			
//			std::wcout << _XPLATSTR("Decoding digest...") << std::endl;
//
//			std::string unhashed = "";
//			unhashed = hashObj.decodeURL(hashed);
//			std::wcout << _XPLATSTR("Decoded digest:	")<<unhashed.c_str() << std::endl;
//
//			/*web::json::value jsonVerification;
//
//			bool rc3 = kvc.GetVerification(kid, algorithm, hash, signValue, jsonVerification);
//			if (rc3 == false) {
//				std::wcout << _XPLATSTR("Cant verify") << std::endl;
//				return 1;
//			}*/
//
//		//	std::wcout << _XPLATSTR("Verification  : ") << jsonVerification << std::endl;
//
//		}
//
//
//		else {
//			std::wcout << _XPLATSTR("Querying KeyVault for Keys ") << action.c_str() << _XPLATSTR("...") << std::endl;
//			web::json::value jsonKey;
//			bool rc = kvc.GetKeyValue(action, jsonKey);
//
//			if (rc == false) {
//				std::wcout << _XPLATSTR("Key doesn't exist") << std::endl;
//				return 1;
//			}
//
//			std::wcout << _XPLATSTR("Key   : ") << (jsonKey[_XPLATSTR("key")]) << std::endl;
//
//
//		}
//
//	}
//
//	else if (type == _XPLATSTR("secret")) {
//		
//		if (action == _XPLATSTR("all")) {
//			std::wcout << _XPLATSTR(" Querying KeyVault for all Secrets  ") << std::endl;
//			web::json::value jsonSecret;
//			action = _XPLATSTR("");
//			bool rc = kvc.GetSecretValue(action, jsonSecret);
//			
//
//			if (rc == false) {
//				/*std::wcout << _XPLATSTR("Secret doesn't exist") << std::endl;*/
//				return 1;
//			}
//
//			std::wcout << _XPLATSTR("Secrets  : ") << jsonSecret << std::endl;
//		}
//
//		else {
//			std::wcout << _XPLATSTR("Querying KeyVault for Secret ") << action.c_str() << _XPLATSTR("...") << std::endl;
//			web::json::value jsonSecret;
//			bool rc = kvc.GetSecretValue(action, jsonSecret);
//
//			if (rc == false) {
//				std::wcout << _XPLATSTR("Secret doesn't exist") << std::endl;
//				return 1;
//			}
//
//			std::wcout  << (jsonSecret[_XPLATSTR("kid")]) << std::endl;
//			std::wcout << _XPLATSTR("Secret ID   : ") << jsonSecret[_XPLATSTR("id")] << std::endl;
//			std::wcout << _XPLATSTR("Secret Value: ") << jsonSecret[_XPLATSTR("value")] << std::endl;
//
//
//		}
//	}
//
//
//	return 0;
//}
//








