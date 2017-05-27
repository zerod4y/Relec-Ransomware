#pragma warning (disable : 4996)

#include "config.h"
#include "CryptOperation.h"
#include "GeneralOperation.h"
#include <string>

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <ctime>

#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define ENCRYPT_BLOCK_SIZE 8 

using namespace std;


#define A(c)            (c) - 0x19
#define UNHIDE_STR(str) do { char *p = str;  while (*p) *p++ += 0x19; } while (0)
#define HIDE_STR(str)   do { char *p = str;  while (*p) *p++ -= 0x19; } while (0)
#define PASSWORD { A('M'), A('y'), A('P'), A('a'), A('a'), A('s'), A('W'), A('o'), A('r'), A('d'), 0 }

CryptOperation::CryptOperation() {
	if (!CryptAcquireContext(&m_hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContext(&m_hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET))
			{
				return;
			}
		}
		else
		{
			return;
		}
	}

	m_hCryptKey = NULL;
}

CryptOperation::~CryptOperation() {
	if (m_hCryptProv)
		if (!(CryptReleaseContext(m_hCryptProv, 0)))
			Error(TEXT("Error during CryptReleaseContext!\n"), GetLastError());
}

std::string CryptOperation::Base64Encode(const std::string &in) {

	std::string out;

	int val = 0, valb = -6;
	for (unsigned char c : in) {
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb>-6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4) out.push_back('=');
	return out;
}

std::string CryptOperation::Base64Decode(const std::string &in) {

	std::string out;

	std::vector<int> T(256, -1);
	for (int i = 0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

	int val = 0, valb = -8;
	for (unsigned char c : in) {
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

string CryptOperation::XOR(string data)
{
	char key[] = PASSWORD;

	string xorstring = data;
	for (int i = 0; i < xorstring.size(); i++) {
		xorstring[i] = data[i] ^ key[i % (sizeof(key) / sizeof(char))];
	}
	return xorstring;
}

bool CryptOperation::LockFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword)
{
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;


	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;

	__try {
		hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hSourceFile)
			__leave;

		hDestinationFile = CreateFile(pszDestinationFile, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hDestinationFile)
			__leave;

		if (m_hCryptProv == NULL)
			__leave;

		if (!CryptCreateHash(m_hCryptProv, CALG_MD5, 0, 0, &hHash))
			__leave;

		if (!CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword), 0))
			__leave;

		if (!CryptDeriveKey(m_hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey))
			__leave;

		dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

		if (ENCRYPT_BLOCK_SIZE > 1)
			dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
		else
			dwBufferLen = dwBlockLen;

		if (!(pbBuffer = (BYTE *)malloc(dwBufferLen)))
			__leave;

		bool fEOF = FALSE;
		do
		{
			if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL))
				__leave;

			if (dwCount < dwBlockLen)
				fEOF = TRUE;

			if (!CryptEncrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBufferLen))
				__leave;

			if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL))
				__leave;


		} while (!fEOF);

		fReturn = true;
	}
	__finally {
		if (hSourceFile)
			CloseHandle(hSourceFile);

		if (hDestinationFile)
			CloseHandle(hDestinationFile);

		if (pbBuffer)
			free(pbBuffer);


		if (hHash)
		{
			if (!(CryptDestroyHash(hHash)))
				Error(TEXT("Error during CryptDestroyHash.\n"), GetLastError());

			hHash = NULL;
		}

		if (hKey)
			if (!(CryptDestroyKey(hKey)))
				Error(TEXT("Error during CryptDestroyKey!\n"), GetLastError());
	}

	return fReturn;
}

void Error(LPTSTR psz, int nErrorNumber);

bool CryptOperation::UnlockFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword)
{
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;

	DWORD dwCount;
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

	__try
	{
		hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hSourceFile)
			__leave;


		hDestinationFile = CreateFile(pszDestinationFile, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hDestinationFile)
			__leave;

		if (m_hCryptProv == NULL)
			__leave;

		if (!CryptCreateHash(m_hCryptProv, CALG_MD5, 0, 0, &hHash))
			__leave;

		if (!CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword), 0))
			__leave;

		if (!CryptDeriveKey(m_hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey))
			__leave;

		dwBlockLen = 1000000000 - 1000000000 % ENCRYPT_BLOCK_SIZE;
		dwBufferLen = dwBlockLen;

		if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
			__leave;

		bool fEOF = false;
		do
		{
			if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL))
				__leave;

			if (dwCount <= dwBlockLen)
				fEOF = TRUE;

			if (!CryptDecrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount))
				__leave;

			if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL))
				__leave;
		} while (!fEOF);

		fReturn = true;
	}
	__finally
	{
		if (pbBuffer)
			free(pbBuffer);

		if (hSourceFile)
			CloseHandle(hSourceFile);

		if (hDestinationFile)
			CloseHandle(hDestinationFile);

		if (hHash)
			if (!(CryptDestroyHash(hHash)))
				Error(TEXT("Error during CryptDestroyHash.\n"), GetLastError());

		hHash = NULL;

		if (hKey && !(CryptDestroyKey(hKey)))
			Error(TEXT("Error during CryptDestroyKey!\n"), GetLastError());
	}

	return fReturn;
}

void CryptOperation::Error(LPTSTR psz, int nErrorNumber)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}

std::string CryptOperation::GenerateRandomPassword()
{
	static const char data[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"*/&%!=-";
	char s[RANDOM_PASSWORD_LENGTH + 1];
	srand(time(NULL));

	for (int i = 0; i < RANDOM_PASSWORD_LENGTH; ++i) {
		s[i] = data[rand() % (sizeof(data) - 1)];
	}

	s[RANDOM_PASSWORD_LENGTH] = 0;
	std::string password(s);
	return password;
}

// Very simple validation progress. You can change is for more secure and robust encryption.
bool CryptOperation::ValidatePassword(std::string const& key)
{
	std::string data = Base64Decode(key);
	std::string computerInfo = GeneralOperation::ComputerName() + GeneralOperation::Username();
	return data.compare(0, computerInfo.size(), computerInfo) == 0;
}

std::string CryptOperation::Encrypt(LPTSTR cleanData)
{
	if (this->m_hCryptProv == NULL)
		return false;

	DWORD dataLen = lstrlen(cleanData);
	DWORD dwSize = dataLen;

	CryptEncrypt(m_hCryptKey, 0, TRUE, 0, NULL, &dwSize, dwSize);
	LPTSTR encryptData = new char[dwSize];
	strcpy(encryptData, cleanData);

	bool cryptResult = CryptEncrypt(m_hCryptKey, NULL, TRUE, 0, (BYTE*)encryptData, &dataLen, dwSize);

	std::string returnValue(encryptData);
	LocalFree(encryptData);

	return returnValue;
}

std::string CryptOperation::Decrypt(LPTSTR encryptData)
{
	if (this->m_hCryptProv == NULL)
		return false;

	DWORD dataLen = lstrlen(encryptData);
	DWORD dwSize = 256;

	bool status = CryptDecrypt(m_hCryptKey, NULL, TRUE, 0, NULL, &dwSize);
	LPTSTR cleanData = new char[dwSize];

	strcpy(cleanData, encryptData);

	bool decryptResult = CryptDecrypt(m_hCryptKey, NULL, TRUE, 0, (BYTE*)cleanData, &dwSize);
	std::string returnValue(cleanData);
	LocalFree(cleanData);

	return returnValue;
}

bool CryptOperation::ImportPrivateKey(char const * pemPubKey)
{
	if (m_hCryptProv == NULL)
		return false;

	if (m_hCryptKey != NULL)
		CryptDestroyKey(m_hCryptKey);

	DWORD dwBufferLen = 0, cbKeyBlob = 0;
	LPBYTE pbBuffer = NULL, pbKeyBlob = NULL;

	__try {
		if (!CryptStringToBinaryA(pemPubKey, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen, NULL, NULL))
			return FALSE;

		pbBuffer = (LPBYTE)LocalAlloc(0, dwBufferLen);
		if (!CryptStringToBinaryA(pemPubKey, 0, CRYPT_STRING_BASE64HEADER, pbBuffer, &dwBufferLen, NULL, NULL))
			return FALSE;

		if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbBuffer, dwBufferLen, 0, NULL, NULL, &cbKeyBlob))
			return FALSE;

		pbKeyBlob = (LPBYTE)LocalAlloc(0, cbKeyBlob);
		if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbBuffer, dwBufferLen, 0, NULL, pbKeyBlob, &cbKeyBlob))
			return FALSE;

		if (!CryptAcquireContext(&m_hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			return FALSE;

		if (!CryptImportKey(m_hCryptProv, pbKeyBlob, cbKeyBlob, NULL, 0, &m_hCryptKey))
			return FALSE;
	}
	__finally
	{
		LocalFree(pbBuffer);
	}

	return TRUE;
}

bool CryptOperation::ImportPublicKey(char const * pemPubKey)
{
	if (m_hCryptProv == NULL)
		return false;

	if (m_hCryptKey != NULL)
		CryptDestroyKey(m_hCryptKey);

	BYTE derPubKey[2048];
	DWORD derPubKeyLen = 2048;
	CERT_PUBLIC_KEY_INFO *publicKeyInfo;
	DWORD publicKeyInfoLen;

	__try {

		if (!CryptStringToBinaryA(pemPubKey, 0, CRYPT_STRING_BASE64HEADER, derPubKey, &derPubKeyLen, NULL, NULL))
			fprintf(stderr, "CryptStringToBinary failed. Err: %d\n", GetLastError());

		if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, derPubKey, derPubKeyLen, CRYPT_ENCODE_ALLOC_FLAG, NULL, &publicKeyInfo, &publicKeyInfoLen))
			return false;

		if (!CryptImportPublicKeyInfo(m_hCryptProv, X509_ASN_ENCODING, publicKeyInfo, &m_hCryptKey))
			return false;
	}
	__finally{
		if (derPubKey)
			LocalFree(derPubKey);

		if (publicKeyInfo)
			free(publicKeyInfo);
	}

	return true;
}