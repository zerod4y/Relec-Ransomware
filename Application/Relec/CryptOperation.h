#pragma once
#include <vector>
#include <tchar.h>
#include <windows.h>
#include <string>

class CryptOperation
{
private:
	HCRYPTPROV m_hCryptProv;
	HCRYPTKEY m_hCryptKey;
	void Error(LPTSTR psz, int nErrorNumber);

public:
	CryptOperation();
	~CryptOperation();

	static std::string GenerateRandomPassword();
	static std::string CryptOperation::XOR(std::string data);

	static std::string Base64Encode(const std::string &in);
	static std::string Base64Decode(const std::string &in);

	static bool ValidatePassword(std::string const& key);

	bool LockFile(LPTSTR szSource, LPTSTR szDestination, LPTSTR szPassword);
	bool UnlockFile(LPTSTR szSource, LPTSTR szDestination, LPTSTR szPassword);

	std::string Decrypt(LPTSTR encryptData);
	std::string Encrypt(LPTSTR cleanData);

	bool ImportPublicKey(char const * pemPubKey);
	bool ImportPrivateKey(char const * pemPubKey);
};

static std::string GetLastErrorAsString1()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string();

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	LocalFree(messageBuffer);
	return message;
}