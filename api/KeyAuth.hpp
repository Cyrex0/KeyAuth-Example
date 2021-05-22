#pragma once
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/ccm.h>

#include <curl/curl.h>

#include <atlsecurity.h> 
#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <openssl/md5.h> 

#include <sstream> 
#include <iomanip> 
#include "xorstr.hpp"
#include <fstream> 

#include <nlohmann/json.hpp>
#include "../lw_http.hpp"

#pragma comment(lib, "rpcrt4.lib")

#define BUFFSIZE 16384
/*
 /$$   /$$                      /$$$$$$              /$$     /$$
| $$  /$$/                     /$$__  $$            | $$    | $$
| $$ /$$/   /$$$$$$  /$$   /$$| $$  \ $$ /$$   /$$ /$$$$$$  | $$$$$$$
| $$$$$/   /$$__  $$| $$  | $$| $$$$$$$$| $$  | $$|_  $$_/  | $$__  $$
| $$  $$  | $$$$$$$$| $$  | $$| $$__  $$| $$  | $$  | $$    | $$  \ $$
| $$\  $$ | $$_____/| $$  | $$| $$  | $$| $$  | $$  | $$ /$$| $$  | $$
| $$ \  $$|  $$$$$$$|  $$$$$$$| $$  | $$|  $$$$$$/  |  $$$$/| $$  | $$
|__/  \__/ \_______/ \____  $$|__/  |__/ \______/    \___/  |__/  |__/
					 /$$  | $$
					|  $$$$$$/
					 \______/

		Copyright KeyAuth �. Use of this code in anything besides
		your c++ application that connects to KeyAuth is prohibited.
*/

namespace KeyAuth {
	std::string GetCurrentDirectory()
	{
		char buffer[MAX_PATH];
		GetModuleFileNameA(NULL, buffer, MAX_PATH);
		std::string::size_type pos = std::string(buffer).find_last_of("\\/");

		return std::string(buffer);
	}
	std::string get_md5hash(const std::string& fname)
	{

		char buffer[BUFFSIZE];
		unsigned char digest[MD5_DIGEST_LENGTH];

		std::stringstream ss;
		std::string md5string;

		std::ifstream ifs(fname, std::ifstream::binary);

		MD5_CTX md5Context;

		MD5_Init(&md5Context);


		while (ifs.good())
		{

			ifs.read(buffer, BUFFSIZE);

			MD5_Update(&md5Context, buffer, ifs.gcount());
		}

		ifs.close();

		int res = MD5_Final(digest, &md5Context);

		if (res == 0) // hash failed 
			return {};   // or raise an exception 

		// set up stringstream format 
		ss << std::hex << std::uppercase << std::setfill('0');


		for (unsigned char uc : digest)
			ss << std::setw(2) << (int)uc;


		md5string = ss.str();

		return md5string;
	}
	class encryption {
	public:
		std::string name;
		static std::string encrypt_string(const std::string& plain_text, const std::string& key, const std::string& iv) {
			std::string cipher_text;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
				encryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

				CryptoPP::StringSource encryptor(plain_text, true,
					new CryptoPP::StreamTransformationFilter(encryption,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(cipher_text),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}
			return cipher_text;
		}

		static std::string decrypt_string(const std::string& cipher_text, const std::string& key, const std::string& iv) {
			std::string plain_text;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
				decryption.SetKeyWithIV((CryptoPP::byte*)key.c_str(), key.size(), (CryptoPP::byte*)iv.c_str());

				CryptoPP::StringSource decryptor(cipher_text, true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StreamTransformationFilter(decryption,
							new CryptoPP::StringSink(plain_text)
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}
			return plain_text;
		}

		static std::string sha256(const std::string& plain_text) {
			std::string hashed_text;
			CryptoPP::SHA256 hash;

			try {
				CryptoPP::StringSource hashing(plain_text, true,
					new CryptoPP::HashFilter(hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(hashed_text),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}

			return hashed_text;
		}

		static std::string encode(const std::string& plain_text) {
			std::string encoded_text;

			try {
				CryptoPP::StringSource encoding(plain_text, true,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(encoded_text),
						false
					)
				);
			}
			catch (CryptoPP::Exception& ex) {
				system(XorStr("cls").c_str());
				std::cout << ex.what();
				exit(0);
			}

			return encoded_text;
		}

		static std::string iv_key() {
			UUID uuid = { 0 };
			std::string guid;

			::UuidCreate(&uuid);

			RPC_CSTR szUuid = NULL;
			if (::UuidToStringA(&uuid, &szUuid) == RPC_S_OK)
			{
				guid = (char*)szUuid;
				::RpcStringFreeA(&szUuid);
			}

			return guid.substr(0, 16);
		}

		static std::string encrypt(std::string message, std::string enc_key, std::string iv) {
			enc_key = sha256(enc_key).substr(0, 32);
			iv = sha256(iv).substr(0, 16);
			return encrypt_string(message, enc_key, iv);
		}

		static std::string decrypt(std::string message, std::string enc_key, std::string iv) {
			enc_key = sha256(enc_key).substr(0, 32);

			iv = sha256(iv).substr(0, 16);

			return decrypt_string(message, enc_key, iv);
		}
	};

	class utils {
	public:

		static std::string get_hwid() {
			ATL::CAccessToken accessToken;
			ATL::CSid currentUserSid;
			if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
				accessToken.GetUser(&currentUserSid))
				return std::string(CT2A(currentUserSid.Sid()));
		}

		static std::time_t string_to_timet(std::string timestamp) {
			auto cv = strtol(timestamp.c_str(), NULL, 10);

			return (time_t)cv;
		}

		static std::tm timet_to_tm(time_t timestamp) {
			std::tm context;

			localtime_s(&context, &timestamp);

			return context;
		}

	};

	auto iv = encryption::sha256(encryption::iv_key());
	class api {

	public:

		std::string name, ownerid, secret, version;

		api(std::string name, std::string ownerid, std::string secret, std::string version)
			: name(name), ownerid(ownerid), secret(secret), version(version) {}

		void init() {
			if (ownerid.length() != 10 || secret.length() != 64)
			{
				std::cout << XorStr("\n\n Application Not Setup Correctly. Please Wait Video Linked in Main.cpp");
				Sleep(4500);
				exit(0);
			}

			std::string hash = get_md5hash(GetCurrentDirectory());
			auto data =
				XorStr("type=").c_str() + encryption::encode(XorStr("init").c_str()) +
				XorStr("&ver=").c_str() + encryption::encrypt(version, secret, iv) +
				XorStr("&hash=").c_str() + hash +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;

			auto response = req(data);
			
			response = encryption::decrypt(response, secret, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				// optional success message. Make sure to string encrypt for security
			}
			else if (json[("message")] == "invalidver")
			{
				std::string dl = json[("download")];
				ShellExecuteA(0, "open", dl.c_str(), 0, 0, SW_SHOWNORMAL);
				exit(0);
			}
			else
			{
				std::cout << "\n\n ";
				std::cout << std::string(json[("message")]);
				Sleep(4500);
				exit(0);
			}
		}

		bool login(std::string key) {

			std::string hwid = utils::get_hwid();
			auto iv = encryption::sha256(encryption::iv_key());
			auto data =
				XorStr("type=").c_str() + encryption::encode("login") +
				XorStr("&key=").c_str() + encryption::encrypt(key, secret, iv) +
				XorStr("&hwid=").c_str() + encryption::encrypt(hwid, secret, iv) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, secret, iv);
			auto json = response_decoder.parse(response);
		    
			if (json[("success")])
			{
				// optional success message. Make sure to string encrypt for security
				load_user_data(json[("info")]);
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
				return false;
			}
		}

		std::string var(std::string varid) {

			std::string hwid = utils::get_hwid();
			auto iv = encryption::sha256(encryption::iv_key());
			auto data =
				XorStr("type=").c_str() + encryption::encode("var") +
				XorStr("&key=").c_str() + encryption::encrypt(user_data.key, secret, iv) +
				XorStr("&varid=").c_str() + encryption::encrypt(varid, secret, iv) +
				XorStr("&hwid=").c_str() + encryption::encrypt(hwid, secret, iv) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;
			auto response = req(data);
			response = encryption::decrypt(response, secret, iv);
			auto json = response_decoder.parse(response);

			if (json[("success")])
			{
				return json[("message")];
			}
			else
			{
				std::cout << XorStr("\n\n Status: Failure: ");
				std::cout << std::string(json[("message")]);
			}
		}



		void log(std::string message) {

			auto iv = encryption::sha256(encryption::iv_key());
			std::string data =
				XorStr("type=").c_str() + encryption::encode(XorStr("log").c_str()) +
				XorStr("&key=").c_str() + encryption::encrypt(user_data.key, secret, iv) +
				XorStr("&message=").c_str() + encryption::encrypt(message, secret, iv) +
				XorStr("&name=").c_str() + encryption::encode(name) +
				XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
				XorStr("&init_iv=").c_str() + iv;

			req(data);
		}

		void Memory(std::string fileid, std::string& s_reply, std::string output = XorStr("same.exe").c_str(), bool memory = false, unsigned char** ape = nullptr) {
			auto iv = encryption::sha256(encryption::iv_key());
			c_lw_http    lw_http;
			c_lw_httpd    lw_http_d;

			if (!lw_http.open_session())
				MessageBoxA(0, "fail", "ret", 0);

			lw_http_d.add_field(PCHAR("type"), encryption::encode(XorStr("file").c_str()).c_str());
			lw_http_d.add_field(PCHAR("fileid"), encryption::encrypt(fileid, secret, iv).c_str());

			lw_http_d.add_field(PCHAR("name"), encryption::encode(name).c_str());
			lw_http_d.add_field(PCHAR("ownerid"), encryption::encode(ownerid).c_str());
			lw_http_d.add_field(PCHAR("init_iv"), iv.c_str());

			const auto b_lw_http = lw_http.post(L"https://keyauth.com/api/v3/", s_reply, lw_http_d);
			//s_reply = encryption::decrypt(s_reply, secret, iv); // RAW file

			if (memory)
			{
				*ape = (unsigned char*)s_reply.data();
			}
			else // Not loading in memory.
			{
				std::ofstream file(output.c_str(), std::ios_base::out | std::ios_base::binary);
				file.write(s_reply.data(), s_reply.size());
				file.close();
			}

			lw_http.close_session();
		}

		class user_data_class {
		public:
			std::string key;
			std::tm expiry;
			int level;
		};

		user_data_class user_data;

	private:
		static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
			((std::string*)userp)->append((char*)contents, size * nmemb);
			return size * nmemb;
		}


		static std::string req(std::string data) {
			CURL* curl = curl_easy_init();

			if (!curl)
				return "null";

			std::string to_return;

			curl_easy_setopt(curl, CURLOPT_URL, XorStr("https://keyauth.com/api/v3/").c_str());
			curl_easy_setopt(curl, CURLOPT_USERAGENT, XorStr("KeyAuth").c_str());

			curl_easy_setopt(curl, CURLOPT_NOPROXY, XorStr("keyauth.com").c_str());

			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

			curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//UjJQOuTpgenjm6zOasOClsM8Ua6m6IJ09jzwC6YYDh0=");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);

			auto code = curl_easy_perform(curl);

			if (code != CURLE_OK)
				MessageBoxA(0, curl_easy_strerror(code), 0, MB_ICONERROR);

			return to_return;
		}
		class user_data_structure {
		public:
			std::string key;
			std::string expiry;
			int level;
		};

		void load_user_data(nlohmann::json data) {

			user_data.key = data["key"];


			user_data.expiry = utils::timet_to_tm(
				utils::string_to_timet(data["expiry"])
			);

			user_data.level = data["level"];

		}

		nlohmann::json response_decoder;
		
	};
}
