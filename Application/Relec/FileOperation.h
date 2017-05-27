#pragma once
#include <vector>
#include <set>

class FileOperation
{
public:
	static int SearchDirectory(std::vector < std::string > &refvecFiles,
		const std::string &refcstrRootDirectory,
		const std::set < std::string > &refcstrExtension,
		bool bSearchSubdirectories = true);

	static void SetDirectory(std::string const & path);
	static std::string GetDirectory();
};