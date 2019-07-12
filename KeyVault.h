#ifndef KEYVAULT_H__
#define KEYVAULT_H__
#pragma once
#include "cpprest/http_client.h"
#include "cpprest/containerstream.h"
#include "cpprest/filestream.h"

#ifdef _WIN32
#include <time.h>
#include <objbase.h>
#include <algorithm>
#include <functional>
#include <iostream>

#else
#include <sys/time.h>
#include <uuid/uuid.h>
#endif


class KeyVault
{
private:
	//Authorization variables
	utility::string_t tokenType;		//Authorization token type
	utility::string_t accessToken;		//Authorization access token

	//Client code authentication

	//Device Code Authentication
	utility::string_t deviceCode;		//Auth 2.0 device code
	utility::string_t interval;			//Refresh access request interval
	utility::string_t expiresIn;		//Expiry time of device code.

	utility::string_t loginUrl;			//Login URL 
	utility::string_t resourceUrl;		//Resource URL
	utility::string_t keyVaultName;		//Key Vault Name
	utility::string_t keyVaultRegion;	//Key Vault Region
	utility::string_t subscriptionID;	//Azure Subscription ID
	
	web::json::value secret;			//Secret Value
	web::json::value key;				//Key value
	web::json::value signature;			//Sign Response
	web::json::value verification;		//Verify Response
	web::json::value cert;				//Certificate value

	int status_code;					//Status code (200,400,401)

	//Date time
	utility::datetime codeExpiresOn;

//METHODS

private:

	//Make a HTTP Get to Azure KeyVault unauthorized which gets us a response 
	//where the header contains the url of Identity provider to be used
	pplx::task<void> AuthenticateKeyVault(utility::string_t& keyVaultName);
	//Device Authorization Request
	pplx::task<void> getDeviceCode(utility::string_t& clientId);
	//Client Code Authorization
	pplx::task<void> getClientAuthCode(utility::string_t & clientId);
	//Device code polling to Authenticate 
	void Authenticate(utility::string_t& clientId);

	//Runtime Tasks
	//Get a specified secret from a given key vault.
	pplx::task<void> get_secret(utility::string_t secretName);
	//Gets the public part of a stored key.
	pplx::task<void> get_key(utility::string_t secretName);
	//Creates a signature from a digest using the specified key.
	pplx::task<void> sign(utility::string_t secretName, utility::string_t, utility::string_t );
	//Verifies a signature using a specified key.
	pplx::task<void> verify(utility::string_t secretName, utility::string_t algorithm, utility::string_t string1, utility::string_t signValue);
	//Creates a new key, stores it, then returns key parameters and attributes to the client.
	pplx::task<void> createKey(utility::string_t& keyname, utility::string_t& keytype, utility::string_t& keysize);
	//Creates a new certificate.
	pplx::task<void> createCert(utility::string_t certName, utility::string_t subject);
	//Merges a certificate or a certificate chain with a key pair existing on the server.
	pplx::task<void> mergeCertificate(utility::string_t certName, utility::string_t fileName);
	//Gets the creation operation of a certificate.
	pplx::task<void> getCSR(utility::string_t certName);
	//List subscriptions (**)
	pplx::task<void> listSubscriptions();


	//Helper Functions 
	/*parse out https url in double quotes*/
	utility::string_t get_https_url(utility::string_t headerValue);
	/*Make a HTTP Get to Azure KeyVault unauthorized which gets us a response
	where the header contains the url of IDP to be used*/
	void GetLoginUrl();
	/* Generate a new guid */
	utility::string_t NewGuid();
	/*Read Web response body to string value */
	utility::string_t read_response_body(web::http::http_response response);
	//Convert to date time utility
	void convertTime(utility::string_t expiresIn);
	void eraseAllSubStr(utility::string_t & mainStr, const utility::string_t & toErase);
	

public:
	//CONSTRUCTORS
	KeyVault();
	KeyVault(utility::string_t & keyVault_Name, utility::string_t & access_token, utility::string_t & token_type);
	void createAuthorizationURL(utility::string_t& keyVaultName, utility::string_t&  access_token, utility::string_t& token_type);

	//Authenticate Calls to  Azure KeyVault REST API
	//Unauthorized Request
	int GetAuthenticateKeyVaultResponse(utility::string_t& keyVaultName);
	//Device Code Request
	int GetDeviceCodeResponse(utility::string_t& clientId);
	//Authentication Response, after Device code TOKEN
	int GetAuthenticateResponse(utility::string_t& clientId);
	//Authentication Response, after Client auth code TOKEN
	int GetClientAuthCodeResponse(utility::string_t & clientId);


	//KEY VAULT OPERATIONS
	//Response, after request to download CSR
	bool getCSRResponse(utility::string_t certName, web::json::value & response);
	//Response, after request to Get Access TOKEN
	bool GetAccessToken(utility::string_t & clientId, utility::string_t & access_token, utility::string_t & token_type);
	//Response, after request to Get Secret from KeyVault
	bool GetSecretValue(utility::string_t secretName, web::json::value& secret);
	//Response, after Merging Certificate too Certificate Request 
	bool mergedCert(utility::string_t certName, utility::string_t fileName, web::json::value &);
	//Response, after Call to Azure KeyVault REST API to GET KEY
	bool GetKeyValue(utility::string_t secretName, web::json::value& key);
	//Response after Call Azure KeyVault REST API to SIGN
	bool GetSignature(utility::string_t secretName, utility::string_t, utility::string_t, web::json::value& signature);
	//Response, after Call Azure KeyVault REST API to VERIFY
	bool GetVerification(utility::string_t secretName, utility::string_t, utility::string_t, utility::string_t signValue, web::json::value& verification);
	//Response, after Call Azure KeyVault REST API to CREATE KEY
	bool createdKey(utility::string_t & keyname, utility::string_t & keytype, utility::string_t & keysize);
	//Response, after Call Azure KeyVault REST API to CREATE CERTIFICATE
	bool createdCert(utility::string_t certName, utility::string_t subject, web::json::value &);
	
};

#endif

