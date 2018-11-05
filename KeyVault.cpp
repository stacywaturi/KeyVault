#include "KeyVault.h"
#include "cpprest/asyncrt_utils.h"

KeyVault::KeyVault() {

	this->tokenType	= utility::string_t();				this->accessToken	= utility::string_t();
	this->deviceCode = utility::string_t();				this->interval = utility::string_t();
	this->expiresIn = utility::string_t();				this->loginUrl = utility::string_t();
	this->resourceUrl = utility::string_t();			this->keyVaultName = utility::string_t();
	this->keyVaultRegion = utility::string_t();			this->subscriptionID = utility::string_t();

	this->secret = web::json::value();					this->key = web::json::value();
	this->signature = web::json::value();				this->verification = web::json::value();
	this->cert = web::json::value();
	this->status_code = 0;
}

KeyVault::KeyVault(utility::string_t& keyVault_Name, utility::string_t& access_token, utility::string_t& token_type) {
	this->keyVaultName = keyVault_Name;
	this->accessToken = access_token;
	this->tokenType = token_type;
}


/********************************
AUTHENTICATION
*********************************/

void KeyVault::createAuthorizationURL(utility::string_t& keyVault_Name, utility::string_t& access_token, utility::string_t& token_type) {
	auto impl = this;
	impl->keyVaultName = keyVault_Name;
	impl->accessToken = access_token;
	impl->tokenType = token_type;

}

/* Call Azure KeyVault REST API to AUTHENTICATE (false)
*/
int KeyVault::GetAuthenticateKeyVaultResponse(utility::string_t& keyVaultName)
{
	AuthenticateKeyVault(keyVaultName).wait();

	return this->status_code;
}

/* Makes a HTTP GET to your KeyVault endpoint asking for a bogus secret
Grabs the OAuth endpoint in the header of the Response
*/
pplx::task<void> KeyVault::AuthenticateKeyVault(utility::string_t& keyVaultName)
{
	//std::wcout << _XPLATSTR("Login Successful") << std::endl;
	auto impl = this;
	impl->keyVaultName = keyVaultName;
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/secretname?api-version=2015-06-01");
	//std::wcout << std::endl << _XPLATSTR("REQUEST TO  URL	:");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	return client.request(web::http::methods::GET).then([impl](web::http::http_response response)
	{
		//std::wcout << std::endl << _XPLATSTR("UNAUTHORIZED RESPONSE	:");
		//std::wcout << response.to_string() << std::endl;
		impl->status_code = response.status_code();
		if (impl->status_code == 401) {
			web::http::http_headers& headers = response.headers();
			impl->keyVaultRegion = headers[_XPLATSTR("x-ms-keyvault-region")];
			const utility::string_t& wwwAuth = headers[_XPLATSTR("WWW-Authenticate")];
			// parse WWW-Authenticate header into url links. Format:
			// Bearer authenticate="url", resource="url"
			utility::string_t delimiter = _XPLATSTR(" ");
			size_t count = 0, start = 0, end = wwwAuth.find(delimiter);
			while (end != utility::string_t::npos)
			{
				utility::string_t part = wwwAuth.substr(start, end - start);
				if (count == 1) {
					impl->loginUrl = impl->get_https_url(part);
				}
				start = end + delimiter.length();
				end = wwwAuth.find(delimiter, start);
				count++;
			}
			utility::string_t part = wwwAuth.substr(start, end - start);
			impl->resourceUrl = impl->get_https_url(part);
		}
	});

}

/* Call Azure KeyVault REST API to REQUEST DEVICE CODE
*/
int KeyVault::GetDeviceCodeResponse(utility::string_t& clientId)
{
	getDeviceCode(clientId).wait();
	return this->status_code;
}

/*Device Authorization Request*/
pplx::task<void> KeyVault::getDeviceCode(utility::string_t& clientId) {
	auto impl = this;
	// create the oauth2 authentication request and pass the clientId/Secret as app identifiers h
	utility::string_t url = impl->loginUrl + _XPLATSTR("/oauth2/devicecode")/*+_XPLATSTR("client_id=") + clientId + _XPLATSTR("&response_type=code")*/;
	//std::wcout << std::endl << _XPLATSTR("REQUEST TO  GET DEVICE CODE	:");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);

	utility::string_t postData = _XPLATSTR("resource=") + web::uri::encode_uri(impl->resourceUrl) + _XPLATSTR("&client_id=") + clientId;
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/x-www-form-urlencoded"));
	request.headers().add(_XPLATSTR("Content-Length"), _XPLATSTR("455"));
	request.headers().add(_XPLATSTR("Expect"), _XPLATSTR("100-continue"));
	request.headers().add(_XPLATSTR("Connection"), _XPLATSTR("Keep-Alive"));
	request.set_body(postData);
	//std::wcout << request.to_string() << std::endl;
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << std::endl << _XPLATSTR("RESPONSE :") << response.to_string() << std::endl;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			//std::wcout << _XPLATSTR("Device Code Success") << std::endl;
			utility::string_t target = impl->read_response_body(response);
			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);

			if (err.value() == 0) {
				impl->deviceCode = jwtToken[_XPLATSTR("device_code")].as_string();
				impl->expiresIn = jwtToken[_XPLATSTR("expires_in")].as_string();
				impl->interval = jwtToken[_XPLATSTR("interval")].as_string();
			}
		}

	});
}



/* Call Azure KeyVault REST API to Authenticate Request Client Credentials Grant 
*/
int KeyVault::GetClientAuthCodeResponse(utility::string_t& clientId)
{
	getClientAuthCode(clientId).wait();
	return this->status_code;
}

/*Client Code Authorization Request*/
pplx::task<void> KeyVault::getClientAuthCode(utility::string_t& clientId) {
	auto impl = this;
	// create the oauth2 authentication request and pass the clientId/Secret as app identifiers h
	utility::string_t url = impl->loginUrl + _XPLATSTR("/oauth2/token");/*+_XPLATSTR("client_id=") + clientId + _XPLATSTR("&response_type=code")*/
	//std::wcout << std::endl << _XPLATSTR("REQUEST TO  GET CLIENT AUTH CODE	:");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);

	utility::string_t username = _XPLATSTR("stacy@isolvtech.com");
	utility::string_t password = _XPLATSTR("100#I100s100l");


	utility::string_t postData = _XPLATSTR("resource=") + web::uri::encode_uri(impl->resourceUrl) + _XPLATSTR("&grant_type=password") + _XPLATSTR("&client_id=") 
								+ clientId + _XPLATSTR("&username=") + username + _XPLATSTR("&password=") + password;
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/x-www-form-urlencoded"));
	request.headers().add(_XPLATSTR("Content-Length"), _XPLATSTR("455"));
	request.headers().add(_XPLATSTR("Expect"), _XPLATSTR("100-continue"));
	request.headers().add(_XPLATSTR("Connection"), _XPLATSTR("Keep-Alive"));
	request.set_body(postData);
	//std::wcout << request.to_string() << std::endl;
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << std::endl << _XPLATSTR("RESPONSE :") << response.to_string() << std::endl;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			//std::wcout << _XPLATSTR("Device Code Success") << std::endl;
			utility::string_t target = impl->read_response_body(response);
			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);

			if (err.value() == 0) {
				impl->tokenType = jwtToken[_XPLATSTR("token_type")].as_string();
				impl->accessToken = jwtToken[_XPLATSTR("access_token")].as_string();
			}
		}

	});
}


/*Call to get ACCESS TOKEN*/
bool KeyVault::GetAccessToken(utility::string_t& clientId, utility::string_t&access_token, utility::string_t&token_type) {
	Authenticate(clientId);
	access_token = this->accessToken;
	token_type = this->tokenType;
	return this->status_code == 200;
}

/*Call to AUTHENTICATE*/
int KeyVault::GetAuthenticateResponse(utility::string_t& clientId)
{
	Authenticate(clientId);
	return this->status_code;
}


/* AUTHENTICATE WITH DEVICE CODE
Make a HTTP POST to oauth2 IDP source to get JWT Token containing
 ACCESS TOKEN & TOKEN TYPE
*/
void KeyVault::Authenticate(utility::string_t& clientId)
{
	auto impl = this;

	convertTime(impl->expiresIn);
	int difference = operator-(impl->codeExpiresOn, utility::datetime::utc_now());

	//Request Device Code
	utility::string_t device_code = impl->deviceCode;
	// create the oauth2 authentication request and pass the clientId/Secret as app identifiers
	utility::string_t url = impl->loginUrl + _XPLATSTR("/oauth2/token");
	//std::wcout << std::endl << _XPLATSTR("REQUEST TO  GET ACCESS TOKEN	:");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	utility::string_t postData = _XPLATSTR("resource=") + web::uri::encode_uri(impl->resourceUrl) + _XPLATSTR("&client_id=") + clientId
		+ _XPLATSTR("&code=") + device_code + _XPLATSTR("&grant_type=device_code");


	//std::wcout << request.to_string() << std::endl;
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	do
	{
		//std::wcout << _XPLATSTR(" Not Expired:") << std::endl;

		web::http::http_request request(web::http::methods::POST);

		request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/x-www-form-urlencoded"));
		request.headers().add(_XPLATSTR("Content-Length"), _XPLATSTR("89"));
		request.headers().add(_XPLATSTR("Expect"), _XPLATSTR("100-continue"));
		
		request.set_body(postData);

		pplx::task<web::http::http_response> resp = client.request(request);
		resp.wait();
		bool done = resp.is_done();

		web::http::http_response response = resp.get();
		//std::wcout << std::endl << _XPLATSTR("RESPONSE	:") << response.to_string() << std::endl;
		impl->status_code = response.status_code();
		

		if (impl->status_code == 200) {
			//std::wcout << _XPLATSTR("Login Successful") << std::endl;
			utility::string_t target = impl->read_response_body(response);
			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				impl->tokenType = jwtToken[_XPLATSTR("token_type")].as_string();
				impl->accessToken = jwtToken[_XPLATSTR("access_token")].as_string();
			}
			break;
		}

		else
		{
			if (difference == 1) {
				std::wcout << _XPLATSTR("EXPIRED	...") << std::endl;
				break;
			}
			//	std::wcout << _XPLATSTR("Still checking") << std::endl;
		}


		difference = operator-(impl->codeExpiresOn, utility::datetime::utc_now());
	
	} while (difference > 0);

}

/******************************************************
CREATE CERT
*******************************************************/

/* Call Azure KeyVault REST API to CREATE KEY
*/
bool KeyVault::createdCert(utility::string_t certName, utility::string_t subject, web::json::value &cert)
{
	createCert(certName, subject).wait();
	cert = this->cert;
	return this->status_code == 202;
}


/*Creates a new certificate.
If this is the first version, the certificate resource is created. 
This operation requires the certificates/create permission.
--------------------------------------------------------------------------------
POST {vaultBaseUrl}/certificates/{certificate-name}/create?api-version=2016-10-01

Request Body:
"policy":{ 
	"x509_props":{
		"subject": "CN=name123"
		}, 
	"issuer":{
		"name":"Self"/"Unknown"}
--------------------------------------------------------------------------------
*/
pplx::task<void>  KeyVault::createCert(utility::string_t certName, utility::string_t subject) {
	auto impl = this;
	
	//utility::string_t certName = _XPLATSTR("myCert11");
	//utility::string_t subject = _XPLATSTR("CN=MyCertSubject11");
	utility::string_t issuer = _XPLATSTR("Unknown");

	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/certificates/") + certName + _XPLATSTR("/create?api-version=2016-10-01");
	
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());

	//Add
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	web::json::value postData;

	postData[L"policy"][L"x509_props"][L"subject"] = web::json::value::string(subject);
	postData[L"policy"][L"issuer"][L"name"] = web::json::value::string(issuer);


	request.set_body(postData);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 202) {

			utility::string_t target = impl->read_response_body(response);
			impl->cert = web::json::value::parse(target.c_str(), err);
		}
		else {
			utility::string_t target = impl->read_response_body(response);
			impl->cert = web::json::value::parse(target.c_str(), err);
		}
	});
}



/******************************************************
CREATE KEY
*******************************************************/
	
/* Call Azure KeyVault REST API to CREATE KEY
*/
bool KeyVault::createdKey(utility::string_t& keyname, utility::string_t& keytype, utility::string_t& keysize)
{
	createKey(keyname, keytype, keysize).wait();
	return this->status_code == 200;
}


/*Creates a new key, stores it, then returns key parameters and attributes to the client.
The create key operation can be used to create any key type in Azure Key Vault.
If the named key already exists, Azure Key Vault creates a new version of the key.
It requires the keys/create permission.
--------------------------------------------------------------------------------
POST {vaultBaseUrl}/keys/{key-name}/create?api-version=2016-10-01

Request Body: kty{RSA,EC}, key_size{int}
--------------------------------------------------------------------------------
*/
pplx::task<void>  KeyVault::createKey(utility::string_t& keyname, utility::string_t& keytype, utility::string_t& keysize) {
	auto impl = this;
	//utility::string_t keyname = _XPLATSTR("key-name");


	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/keys/") + keyname + _XPLATSTR("/create?api-version=2016-10-01");
	//utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/secretname?api-version=2015-06-01");
	web::http::client::http_client client(url);
	//std::wcout << url << std::endl;
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());

	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	web::json::value postData;

	postData[L"kty"] = web::json::value::string(keytype);
	postData[L"key_size"] = web::json::value::string(keysize);


	request.set_body(postData);
	//::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;


		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}


/******************************************************
GET CSR & CERT
*******************************************************/

/* Call Azure KeyVault REST API to GET CSR
*/
bool KeyVault::getCSRResponse(utility::string_t certName, web::json::value &response)
{

	getCSR(certName).wait();
	response = this->cert;
	return this->status_code == 200;
}


/*Gets the creation operation of a certificate.
Gets the creation operation associated with a specified certificate. 
This operation requires the certificates/get permission.
--------------------------------------------------------------------------------
GET {vaultBaseUrl}/certificates/{certificate-name}/pending?api-version=2016-10-01
--------------------------------------------------------------------------------
*/
pplx::task<void>  KeyVault::getCSR(utility::string_t certName) {
	auto impl = this;

//	utility::string_t certName = _XPLATSTR("myCert1");
	

	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/certificates/") + certName + _XPLATSTR("/pending?api-version=2016-10-01");
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;

			impl->cert = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;

		}
		else {
			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;

			impl->cert = web::json::value::parse(target.c_str(), err);
		}
	});
}



/******************************************************
MERGE CERT
*******************************************************/

/* Call Azure KeyVault REST API to MERGE CERTIFICATE
*/
bool KeyVault::mergedCert(utility::string_t certName, utility::string_t fileName, web::json::value & jsonCert)
{
	mergeCertificate(certName, fileName).wait();
	jsonCert = this->cert;
	return this->status_code == 201;
}


/*Creates a new certificate.
If this is the first version, the certificate resource is created.
This operation requires the certificates/create permission.
--------------------------------------------------------------------------------
POST {vaultBaseUrl}/certificates/{certificate-name}/pending/merge?api-version=2016-10-01

Request Body:
{
"x5c": [ MIICxTCCAbi…………EPAQj8=
 ]
}
--------------------------------------------------------------------------------
*/
pplx::task<void>  KeyVault::mergeCertificate(utility::string_t certName, utility::string_t fileName) {
	auto impl = this;


	utility::ifstream_t inFile;
	inFile.open(fileName);

	utility::stringstream_t strStream;
	strStream << inFile.rdbuf();
	utility::string_t cert = strStream.str();

	std::vector<utility::string_t> strList = {_XPLATSTR("-----BEGIN CERTIFICATE-----\n"),_XPLATSTR("\n-----END CERTIFICATE-----")};
	for (std::vector<utility::string_t>::const_iterator it = strList.begin(); it != strList.end(); it++)
	{
		eraseAllSubStr(cert, *it);
	}

	//std::wcout << cert << std::endl;

	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/certificates/") + certName + _XPLATSTR("/pending/merge?api-version=2016-10-01");

	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());

	//Add
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	web::json::value postData;

	postData[L"x5c"] = web::json::value::array(1);

	postData[L"x5c"].as_array()[0] = web::json::value::string(utility::conversions::to_string_t(cert));
	
	request.set_body(postData);
	//std::wcout << request.to_string() << std::endl;

	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 201) {

			utility::string_t target = impl->read_response_body(response);
			impl->cert = web::json::value::parse(target.c_str(), err);

		}
		else {
			
			utility::string_t target = impl->read_response_body(response);
			impl->cert = web::json::value::parse(target.c_str(), err);
		}
	});
}

void KeyVault::eraseAllSubStr(utility::string_t & mainStr, const utility::string_t & toErase)
{
	//std::string mainStr1 = utility::conversions::to_utf8string(mainStr);
	size_t pos = std::string::npos;

	// Search for the substring in string in a loop untill nothing is found
	while ((pos = mainStr.find(toErase)) != std::string::npos)
	{
	
	
		// If found then erase it from string
		mainStr.erase(pos, toErase.length());
	}
}

/******************************************************
		GET KEYS, SECRETS
*******************************************************/

/* Call Azure KeyVault REST API to GET KEY
*/
bool KeyVault::GetKeyValue(utility::string_t secretName, web::json::value &secret)
{
	get_key(secretName).wait();
	secret = this->key;
	return this->status_code == 200;
}

/* Gets the public part of a stored key.
The get key operation is applicable to all key types.
If the requested key is symmetric, then no key material is released in the response.
This operation requires the keys/get permission.
--------------------------------------------------------------------------------
GET {vaultBaseUrl}/keys/{key-name}/{key-version}?api-version=2016-10-01
--------------------------------------------------------------------------------
*/
pplx::task<void> KeyVault::get_key(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/keys/") + secretName + _XPLATSTR("?api-version=2015-06-01");
	//utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/keys/")
	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;


			impl->key = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;

		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}

/* Call Azure KeyVault REST API to GET SECRET
*/
bool KeyVault::GetSecretValue(utility::string_t secretName, web::json::value &secret)
{
	get_secret(secretName).wait();
	secret = this->secret;
	return this->status_code == 200;
}

/* Get a specified secret from a given key vault.
The GET operation is applicable to any secret stored in Azure Key Vault. 
This operation requires the secrets/get permission
--------------------------------------------------------------------------------
GET {vaultBaseUrl}/secrets/{secret-name}/{secret-version}?api-version=2016-10-01
--------------------------------------------------------------------------------
*/
pplx::task<void> KeyVault::get_secret(utility::string_t secretName)
{
	auto impl = this;
	// create the url path to query the keyvault secret
	utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/") + secretName + _XPLATSTR("?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;

			impl->secret = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;

		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}


/******************************************************
SIGN & VERIFY
*******************************************************/

/* Call Azure KeyVault REST API to SIGN
*/
bool KeyVault::GetSignature(utility::string_t kid, utility::string_t algorithm, utility::string_t string1, web::json::value& signature)
{
	sign(kid,algorithm,string1).wait();
	signature = this->signature;
	return this->status_code == 200;
}


/*Creates a signature from a digest using the specified key.
The SIGN operation is applicable to asymmetric and symmetric keys stored in Azure Key Vault since
this operation uses the private portion of the key. 
This operation requires the keys/sign permission.
--------------------------------------------------------------------------------
POST {vaultBaseUrl}/keys/{key-name}/{key-version}/sign?api-version=2016-10-01

Request Body: alg{signing/verification algorithm identifier}, value{string}
--------------------------------------------------------------------------------
*/
pplx::task<void> KeyVault::sign(utility::string_t kid, utility::string_t algorithm, utility::string_t string1)
{
	auto impl = this;
	// create the url path to query the keyvault key
	utility::string_t url = kid + _XPLATSTR("/sign?api-version=2015-06-01");

	web::http::client::http_client client(url);
//	std::wcout << string1.length() << std::endl;
	web::json::value postData;
	postData[U("alg")] = web::json::value::string(algorithm);
	postData[U("value")] = web::json::value::string(string1);

	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	request.set_body(postData);

//	std::wcout << request.to_string() << std::endl;
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{

		//std::wcout << response.to_string() << std::endl;

		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);

			impl->signature = web::json::value::parse(target.c_str());

			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				utility::string_t target = impl->read_response_body(response);
				//std::wcout << target << std::endl;
				//std::wcout << _XPLATSTR("SUCCESS") << std::endl;
			}
		}
	});
}

/* Call Azure KeyVault REST API to VERIFY
*/
bool KeyVault::GetVerification(utility::string_t key, utility::string_t algorithm, utility::string_t string1, utility::string_t signValue, web::json::value& verification)
{
	verify(key, algorithm, string1, signValue).wait();
	verification = this->verification;
	return this->status_code == 200;
}

/*Verifies a signature using a specified key.
The VERIFY operation is applicable to symmetric keys stored in Azure Key Vault.
VERIFY is not strictly necessary for asymmetric keys stored in Azure Key Vault since 
signature verification can be performed using the public portion of the key but 
this operation is supported as a convenience for callers that only have a key-reference
and not the public portion of the key. 
This operation requires the keys/verify permission
--------------------------------------------------------------------------------
POST {vaultBaseUrl}/keys/{key-name}/{key-version}/verify?api-version=2016-10-01

Request Body: alg{signing/verification algorithm identifier}, digest{signing digest}, value{signature}
--------------------------------------------------------------------------------
*/
pplx::task<void> KeyVault::verify(utility::string_t kid, utility::string_t algorithm, utility::string_t string1, utility::string_t signValue)
{
	auto impl = this;
	// create the url path to query the keyvault key
	utility::string_t url = kid + _XPLATSTR("/verify?api-version=2015-06-01");

	//std::wcout << url << std::endl;
	web::http::client::http_client client(url);

	web::json::value postData;

	postData[L"alg"] = web::json::value::string(algorithm);
	postData[L"digest"] = web::json::value::string(string1);
	postData[L"value"] = web::json::value::string(signValue);


	web::http::http_request request(web::http::methods::POST);
	request.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	request.set_body(postData);

	//std::wcout << request.to_string() << std::endl;
	// response from IDP is a JWT Token that contains the token type and access token we need for
	// Azure HTTP REST API calls
	return client.request(request).then([impl](web::http::http_response response)
	{

		//std::wcout << response.to_string() << std::endl;

		impl->status_code = response.status_code();
		if (impl->status_code == 200) {
			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;
			impl->verification = web::json::value::parse(target.c_str());

			std::error_code err;
			web::json::value jwtToken = web::json::value::parse(target.c_str(), err);
			if (err.value() == 0) {
				utility::string_t target = impl->read_response_body(response);
				//std::wcout << target << std::endl;
				//std::wcout << _XPLATSTR("Failed") << std::endl;
			}
		}
	});
}


/* List Subscriptions
*/
pplx::task<void>  KeyVault::listSubscriptions() {
	auto impl = this;

	utility::string_t url = _XPLATSTR("https://management.azure.com/subscriptions/") + impl->subscriptionID + _XPLATSTR("?api-version=2018-07-01");
	//utility::string_t url = _XPLATSTR("https://") + impl->keyVaultName + _XPLATSTR(".vault.azure.net/secrets/secretname?api-version=2015-06-01");
	web::http::client::http_client client(url);
	//std::wcout << url << std::endl;
	web::http::http_request request(web::http::methods::GET);
	request.headers().add(_XPLATSTR("Accept"), _XPLATSTR("application/json"));
	request.headers().add(_XPLATSTR("client-request-id"), NewGuid());
	// add access token we got from authentication step
	request.headers().add(_XPLATSTR("Authorization"), impl->tokenType + _XPLATSTR(" ") + impl->accessToken);
	//std::wcout << request.to_string() << std::endl;
	// Azure HTTP REST API call
	return client.request(request).then([impl](web::http::http_response response)
	{
		//std::wcout << response.to_string() << std::endl;
		std::error_code err;
		impl->status_code = response.status_code();
		if (impl->status_code == 200) {

			utility::string_t target = impl->read_response_body(response);
			//std::wcout << target << std::endl;


			impl->secret = web::json::value::parse(target.c_str(), err);
			//std::wcout << impl->secret << std::endl;

		}
		else {
			impl->secret = web::json::value::parse(_XPLATSTR("{\"id\":\"\",\"value\":\"\"}"), err);
		}
	});
}



/***************************
HELPER FUNCTIONS
****************************/
/* helper to parse out https url in double quotes
*/
utility::string_t KeyVault::get_https_url(utility::string_t headerValue)
{
	size_t pos1 = headerValue.find(_XPLATSTR("https://"));
	if (pos1 >= 0) {
		size_t pos2 = headerValue.find(_XPLATSTR("\""), pos1 + 1);
		if (pos2 > pos1) {
			utility::string_t url = headerValue.substr(pos1, pos2 - pos1);
			headerValue = url;
		}
		else {
			utility::string_t url = headerValue.substr(pos1);
			headerValue = url;
		}
	}
	return headerValue;
}


/* Make a HTTP Get to Azure KeyVault unauthorized which gets us a response 
 where the header contains the url of IDP to be used
*/
void KeyVault::GetLoginUrl()
{
	auto impl = this;
	utility::string_t part;
	impl->loginUrl = impl->get_https_url(_XPLATSTR("https://login.windows.net/common"));
	impl->resourceUrl = impl->get_https_url(_XPLATSTR("https://graph.windows.net"));

}

/* helper to generate a new guid (currently Linux specific, for Windows we
should use ::CoCreateGuid()  */
utility::string_t KeyVault::NewGuid()
{
	utility::string_t guid;
#ifdef _WIN32
	GUID wguid;
	::CoCreateGuid(&wguid);
	wchar_t		uuid_str[38 + 1];
	::StringFromGUID2((const GUID&)wguid, uuid_str, sizeof(uuid_str));
#else
	uuid_t uuid;
	uuid_generate_time_safe(uuid);
	char uuid_str[37];
	uuid_unparse_lower(uuid, uuid_str);
#endif
	guid = uuid_str;
	return guid;
}


/*Read Web response body to string value */
utility::string_t KeyVault::read_response_body(web::http::http_response response)
{
	auto bodyStream = response.body();
	concurrency::streams::stringstreambuf sb;
	auto& target = sb.collection();
	bodyStream.read_to_end(sb).get();
#ifdef _WIN32 // Windows uses UNICODE but result is in UTF8, so we need to convert it
	utility::string_t wtarget;
	wtarget.assign(target.begin(), target.end());
	return wtarget;
#else
	return target;
#endif
}

void KeyVault::convertTime(utility::string_t expiresIn) {
	//Convert ExpiresIn from jwt value to integer
	unsigned int  numb;
	utility::istringstream_t sstr(expiresIn);
	sstr >> numb;

	//Define integer as seconds for c++restsdk
	utility::datetime::interval_type seconds = utility::datetime::from_seconds(numb);

	//Add seconds from expiresIn to the time now
	utility::datetime timeNow = utility::datetime::utc_now();
	codeExpiresOn = timeNow.operator+(seconds);

	//Calculate difference between Time now and Expiry

	int difference = operator-(codeExpiresOn, timeNow);

	//From Response
//	std::wcout << _XPLATSTR("Expires In	:") << expiresIn << std::endl;

	//Configured Variables
	/*std::wcout << _XPLATSTR("Time Now	:") << timeNow.to_string() << std::endl;
	std::wcout << _XPLATSTR("Time Added	:") << codeExpiresOn.to_string() << std::endl;*/


}

