#include "FileOperation.h"

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <algorithm>
#include <string>

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

namespace
{
	std::string executionPath;
}

void FileOperation::SetDirectory(std::string const & path)
{
	executionPath = path;
}

std::string FileOperation::GetDirectory()
{
	return executionPath;
}

int FileOperation::SearchDirectory(std::vector<std::string> &refvecFiles, const std::string&refcstrRootDirectory, const std::set<std::string> &refcstrExtension, bool bSearchSubdirectories)
{
	std::string strFilePath;             
	std::string strPattern(refcstrRootDirectory);            
	std::string strExtension;
	HANDLE hFile;
	WIN32_FIND_DATA FileInformation; 

	std::set <std::string>::const_iterator refEnd = refcstrExtension.cend();

	strPattern = strPattern.append( "\\*.*");

	hFile = ::FindFirstFile(strPattern.c_str(), &FileInformation);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (FileInformation.cFileName[0] != '.')
			{
				strFilePath.erase();
				strFilePath.append(refcstrRootDirectory).append("\\").append(FileInformation.cFileName);

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (bSearchSubdirectories)
					{
						int iRC = SearchDirectory(refvecFiles, strFilePath, refcstrExtension, bSearchSubdirectories);
						if (iRC)
							return iRC;
					}
				}
				else
				{
					strExtension = FileInformation.cFileName;
					strExtension = strExtension.substr(strExtension.rfind(".") + 1);
					std::transform(strExtension.begin(), strExtension.end(), strExtension.begin(), ::tolower);

					if (refcstrExtension.find(strExtension) != refEnd)
						refvecFiles.push_back(strFilePath);
					
				}
			}
		} while (::FindNextFile(hFile, &FileInformation) == TRUE);

		::FindClose(hFile);

		DWORD dwError = ::GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return dwError;
	}

	return 0;
}