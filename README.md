## Relec Ransomware
Ransomware application clone with administration dashboard.

This project only educational purpose. Don't use it for real world application.
Ransomware application is developed at C++ language. Dashboard is developed at Python via flask framework.

Project's video tutorial was uploaded to Youtube and link is below.
https://www.youtube.com/watch?v=8PhgfVFwM7w&t=1s

#### Relec Capabilities
* It use native Windows API. MFC library not used.
* It is targeting spesific extensions.
* Downloading wallpaper from web and changing system wallpaper settings.
* File encryption and decryptions operations.
* Storing encryption key at server.

#### Requirements:
- Python 2.7
- Visual Studio 2015 (Also 2012 can be used via changing project file)

For installing python frameworks:

```pip install flask sqlite3```

Starting dashboard:

```python index.py```

http://127.0.0.1:5000/login

Username : admin

Password : password

#### Ransomeware Configuration
Open config.h and change remote server informations.
```cpp
#define HOST_NAME "127.0.0.1"
#define HOST_PORT 5000 
```

Also you can change wallpaper configuration on same file
```cpp
#define WALLPAPER_HOST "2.bp.blogspot.com"
#define WALLPAPER_PATH "/-M_Zaje-cmlI/UEGFvq6l_tI/AAAAAAAAAJ4/P9lOHN3bt0Q/s1600/ghost+hades+wallpaper.jpg"
#define WALLPAPER_PORT 80
#define WALLPAPER_LOCAL_NAME "\\w.jpg"
```

#### Goals
Malware key encryption via XOR algorithm at now but it have to encrypt with RSA 2048. I got some problem with Wincrypt and OpenSSL migration. Also Bitcoin address will be generate per victims.## Relec Ransomware
Ransomware application clone with administration dashboard.

This project only educational purpose. Don't use it for real world application.
Ransomware application is developed at C++ language. Dashboard is developed at Python via flask framework.

Project's video tutorial was uploaded to Youtube and link is below.
https://www.youtube.com/watch?v=8PhgfVFwM7w&t=1s

#### Relec Capabilities
* It use native Windows API. MFC library not used.
* It is targeting spesific extensions.
* Downloading wallpaper from web and changing system wallpaper settings.
* File encryption and decryptions operations.
* Storing encryption key at server.

#### Requirements:
- Python 2.7
- Visual Studio 2015 (Also 2012 can be used via changing project file)

For installing python frameworks:

```pip install flask sqlite3```

Starting dashboard:

```python index.py```

http://127.0.0.1:5000/login

Username : admin

Password : password

#### Ransomeware Configuration
Open config.h and change remote server informations.
```cpp
#define HOST_NAME "127.0.0.1"
#define HOST_PORT 5000 
```

Also you can change wallpaper configuration on same file
```cpp
#define WALLPAPER_HOST "2.bp.blogspot.com"
#define WALLPAPER_PATH "/-M_Zaje-cmlI/UEGFvq6l_tI/AAAAAAAAAJ4/P9lOHN3bt0Q/s1600/ghost+hades+wallpaper.jpg"
#define WALLPAPER_PORT 80
#define WALLPAPER_LOCAL_NAME "\\w.jpg"
```

#### Goals
Malware key encryption via XOR algorithm at now but it have to encrypt with RSA 2048. I got some problem with Wincrypt and OpenSSL migration. Also Bitcoin address will be generate per victims.