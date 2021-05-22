#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include <sstream>
#include "lazy_importer.hpp"
#include <random>




#undef UNICODE
#define UNICODE
#include <Windows.h>





int runPE64(
	LPPROCESS_INFORMATION lpPI,
	LPSTARTUPINFO lpSI,
	LPVOID lpImage,
	LPWSTR wszArgs,
	SIZE_T szArgs
)
{
	WCHAR wszFilePath[MAX_PATH];
	if (!GetModuleFileName(
		NULL,
		wszFilePath,
		sizeof wszFilePath
	))
	{
		return -1;
	}
	WCHAR wszArgsBuffer[MAX_PATH + 2048];
	ZeroMemory(wszArgsBuffer, sizeof wszArgsBuffer);
	SIZE_T length = wcslen(wszFilePath);
	memcpy(
		wszArgsBuffer,
		wszFilePath,
		length * sizeof(WCHAR)
	);
	wszArgsBuffer[length] = ' ';
	memcpy(
		wszArgsBuffer + length + 1,
		wszArgs,
		szArgs
	);

	PIMAGE_DOS_HEADER lpDOSHeader =
		reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
	PIMAGE_NT_HEADERS lpNTHeader =
		reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<DWORD64>(lpImage) + lpDOSHeader->e_lfanew
			);
	if (lpNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return -2;
	}

	if (!CreateProcess(
		NULL,
		wszArgsBuffer,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		lpSI,
		lpPI
	))
	{
		return -3;
	}

	CONTEXT stCtx;
	ZeroMemory(&stCtx, sizeof stCtx);
	stCtx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(lpPI->hThread, &stCtx))
	{
		TerminateProcess(
			lpPI->hProcess,
			-4
		);
		return -4;
	}

	LPVOID lpImageBase = VirtualAllocEx(
		lpPI->hProcess,
		reinterpret_cast<LPVOID>(lpNTHeader->OptionalHeader.ImageBase),
		lpNTHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (lpImageBase == NULL)
	{
		TerminateProcess(
			lpPI->hProcess,
			-5
		);
		return -5;
	}

	if (!WriteProcessMemory(
		lpPI->hProcess,
		lpImageBase,
		lpImage,
		lpNTHeader->OptionalHeader.SizeOfHeaders,
		NULL
	))
	{
		TerminateProcess(
			lpPI->hProcess,
			-6
		);
		return -6;
	}

	for (
		SIZE_T iSection = 0;
		iSection < lpNTHeader->FileHeader.NumberOfSections;
		++iSection
		)
	{
		PIMAGE_SECTION_HEADER stSectionHeader =
			reinterpret_cast<PIMAGE_SECTION_HEADER>(
				reinterpret_cast<DWORD64>(lpImage) +
				lpDOSHeader->e_lfanew +
				sizeof(IMAGE_NT_HEADERS64) +
				sizeof(IMAGE_SECTION_HEADER) * iSection
				);

		if (!WriteProcessMemory(
			lpPI->hProcess,
			reinterpret_cast<LPVOID>(
				reinterpret_cast<DWORD64>(lpImageBase) +
				stSectionHeader->VirtualAddress
				),
			reinterpret_cast<LPVOID>(
				reinterpret_cast<DWORD64>(lpImage) +
				stSectionHeader->PointerToRawData
				),
			stSectionHeader->SizeOfRawData,
			NULL
		))
		{
			TerminateProcess(
				lpPI->hProcess,
				-7
			);
			return -7;
		}
	}

	if (!WriteProcessMemory(
		lpPI->hProcess,
		reinterpret_cast<LPVOID>(
			stCtx.Rdx + sizeof(LPVOID) * 2
			),
		&lpImageBase,
		sizeof(LPVOID),
		NULL
	))
	{
		TerminateProcess(
			lpPI->hProcess,
			-8
		);
		return -8;
	}

	stCtx.Rcx = reinterpret_cast<DWORD64>(lpImageBase) +
		lpNTHeader->OptionalHeader.AddressOfEntryPoint;
	if (!SetThreadContext(
		lpPI->hThread,
		&stCtx
	))
	{
		TerminateProcess(
			lpPI->hProcess,
			-9
		);
		return -9;
	}

	if (!ResumeThread(lpPI->hThread))
	{
		TerminateProcess(
			lpPI->hProcess,
			-10
		);
		return -10;
	}

	return 0;
}

using namespace KeyAuth;
void error(std::string msg);
void debug();
std::string tm_to_readable_time(tm ctx);
std::string random_string(size_t length);
static std::string RandomProcess();
std::wstring s2ws(const std::string& s);
void input();
DWORD FindProcessId(const std::wstring& processName);
void exedetect();
void titledetect();
void driverdetect();
void killdbg();
void login();

bool running = true;
/*
*
*
* WATCH THIS VIDEO FOR SETUP TUTORIAL: https://youtube.com/watch?v=Uh84xRBYSB0
* DO NOT CONTACT MODMAIL WITHOUT WATCHING VIDEO FIRST
*
*/

std::string name = XorStr("");
std::string ownerid = XorStr("");
std::string secret = XorStr("");
std::string version = XorStr("1.0");

api KeyAuthApp(name, ownerid, secret, version);
std::stringstream dataOut;

size_t dataSize = 0;

size_t write_data(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	dataOut.write((const char*)ptr, size);
	dataSize += size;
	return size;
}

void download(std::string fileid, std::string output) {

	auto iv = encryption::sha256(encryption::iv_key());
	std::string data =
		XorStr("type=").c_str() + encryption::encode(XorStr("file").c_str()) +
		XorStr("&fileid=").c_str() + encryption::encrypt(fileid, secret, iv) +
		XorStr("&name=").c_str() + encryption::encode(name) +
		XorStr("&ownerid=").c_str() + encryption::encode(ownerid) +
		XorStr("&init_iv=").c_str() + iv;

	CURL* curl;


	FILE* fp;


	CURLcode res;
	curl = curl_easy_init();
	if (curl) {
		fp = fopen(output.c_str(), "wb");

		curl_easy_setopt(curl, CURLOPT_URL, XorStr("https://keyauth.com/api/v3/").c_str());
		curl_easy_setopt(curl, CURLOPT_NOPROXY, XorStr("keyauth.com").c_str());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, XorStr("KeyAuth").c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
		curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, "sha256//UjJQOuTpgenjm6zOasOClsM8Ua6m6IJ09jzwC6YYDh0=");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		res = curl_easy_perform(curl);
		/* always cleanup */
		curl_easy_cleanup(curl);
		fclose(fp);
	}
}

unsigned char* file;
unsigned char* explt;
int choice;
int choice2;
std::string s_reply;
int main()
{
	std::thread anti(debug); // you may comment out if you're developing and getting debugger errors.
	SetConsoleTitleA(random_string(12).c_str());
	std::cout << XorStr("\n\n Connecting..");
	KeyAuthApp.init(); // required
	Sleep(2000);
	system("CLS");
	login(); // required

	std::cout << XorStr("\n\n Status: Active: (Expires: ");
	std::cout << tm_to_readable_time(KeyAuthApp.user_data.expiry);
	std::cout << XorStr(")\n ");

	Sleep(500);

	
	
	
	

	
	std::cout << "1.Run Cheat " << std::endl;

	std::cout << "2.Install Exploit " << std::endl;

	
	std::cin >> choice;

	if (choice == 2)
	{
		
		KeyAuthApp.Memory("AppID here", s_reply, {}, true, &file);
																			
	}
	else if (choice == 1) 
	{

		std::cout << "1. Game 1" << std::endl;
		std::cout << "2. Game 2" << std::endl;

		std::cin >> choice2;

		if (choice2 == 1)
		{
			KeyAuthApp.Memory("AppID 1", s_reply, {}, true, &file);
		}
		else if (choice2 == 2)
		{
			KeyAuthApp.Memory("AppID2", s_reply, {}, true, &file);

		}
		else std::cout << "Invalid Choice" << std::endl;
			
			
	}
	else std::cout << "invalid choice" << std::endl;
	
	HWND ConsWind = GetConsoleWindow();
	

	Sleep(3000);

	GlobalAddAtomA(XorStr("b36PXQ3KhzKvfrAz").c_str());
	GlobalAddAtomA(XorStr("h42mVe8AaHStrpVr").c_str());
	GlobalAddAtomA(XorStr("aTc5j7Zj6ZjNKqGC").c_str());

	// runPE here, with dataOut.str() as the data, dataSize as the length of the data, also need to remove process injection stuff
	ShowWindow(ConsWind, 0);
	DWORD dwRet = 0;

	PROCESS_INFORMATION stPI;
	ZeroMemory(&stPI, sizeof stPI);
	STARTUPINFO stSI;
	ZeroMemory(&stSI, sizeof stSI);
	WCHAR szArgs[] = L"";
	if (!runPE64(
		&stPI,
		&stSI,
		reinterpret_cast<LPVOID>(file),
		szArgs,
		sizeof szArgs
	))
	{
		WaitForSingleObject(
			stPI.hProcess,
			INFINITE
		);

		GetExitCodeProcess(
			stPI.hProcess,
			&dwRet
		);

		CloseHandle(stPI.hThread);
		CloseHandle(stPI.hProcess);
	}

	return dwRet;

	//Sleep(-1);

	
}





void login()
{
	if (std::filesystem::exists("C:\\ProgramData\\" + name))
	{
		std::string key;
		std::ifstream InFile("C:\\ProgramData\\" + name, std::ios::in);
		std::getline(InFile, key);

		std::cout << XorStr("\n\n Activating your old license key: ");
		std::cout << key;
		Sleep(1500);

		if (KeyAuthApp.login(key))
		{
		}
		else
		{
			std::string del = "C:\\ProgramData\\" + name;
			remove(del.c_str());
			goto A;
		}
	}
	else
	{
	A:
		std::cout << XorStr("\n\n Please enter your license key: ");
		bool authed = false;
		while (authed == false)
		{
			std::string serial;
			std::cin >> serial;
			if (KeyAuthApp.login(serial)) {
				std::ofstream OutFile("C:\\ProgramData\\" + name, std::ios::out);
				OutFile << serial;
				OutFile.close();
				authed = true;
			}
			else {
				Sleep(2500);
				system("CLS");
				goto A;
			}
		}
	}
}

void input()
{
	while (running)
	{
		int x, y;
		x = 1200;
		y = 1200;
		auto setcur = LI_FN(SetCursorPos);
		setcur(x, y);
		auto blockin = LI_FN(BlockInput);
		blockin(true);
	}
}

static std::string RandomProcess()
{
	std::vector<std::string> Process
	{
		XorStr("winver.exe").c_str(),
		XorStr("Taskmgr.exe").c_str(),
	};
	std::random_device RandGenProc;
	std::mt19937 engine(RandGenProc());
	std::uniform_int_distribution<int> choose(0, Process.size() - 1);
	std::string RandProc = Process[choose(engine)];
	return RandProc;
}

std::wstring s2ws(const std::string& s) {
	std::string curLocale = setlocale(LC_ALL, "");
	const char* _Source = s.c_str();
	size_t _Dsize = mbstowcs(NULL, _Source, 0) + 1;
	wchar_t* _Dest = new wchar_t[_Dsize];
	wmemset(_Dest, 0, _Dsize);
	mbstowcs(_Dest, _Source, _Dsize);
	std::wstring result = _Dest;
	delete[]_Dest;
	setlocale(LC_ALL, curLocale.c_str());
	return result;
}

DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	auto createtoolhelp = LI_FN(CreateToolhelp32Snapshot);
	HANDLE processesSnapshot = createtoolhelp(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		auto closehand = LI_FN(CloseHandle);
		closehand(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			auto closehand = LI_FN(CloseHandle);
			closehand(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	return 0;
}

void exedetect()
{
	if (FindProcessId(s2ws("KsDumperClient.exe")) != 0)
	{
		error(XorStr("KsDumper"));
	}
	else if (FindProcessId(s2ws("HTTPDebuggerUI.exe")) != 0)
	{
		error(XorStr("HTTP Debugger"));
	}
	else if (FindProcessId(s2ws("HTTPDebuggerSvc.exe")) != 0)
	{
		error(XorStr("HTTP Debugger Service"));
	}
	else if (FindProcessId(s2ws("FolderChangesView.exe")) != 0)
	{
		error(XorStr("FolderChangesView"));
	}
	else if (FindProcessId(s2ws("ProcessHacker.exe")) != 0)
	{
		error(XorStr("Process Hacker"));
	}
	else if (FindProcessId(s2ws("procmon.exe")) != 0)
	{
		error(XorStr("Process Monitor"));
	}
	else if (FindProcessId(s2ws("idaq.exe")) != 0)
	{
		error(XorStr("IDA"));
	}
	else if (FindProcessId(s2ws("idaq64.exe")) != 0)
	{
		error(XorStr("IDA"));
	}
	else if (FindProcessId(s2ws("Wireshark.exe")) != 0)
	{
		error(XorStr("WireShark"));
	}
	else if (FindProcessId(s2ws("Fiddler.exe")) != 0)
	{
		error(XorStr("Fiddler"));
	}
	else if (FindProcessId(s2ws("Xenos64.exe")) != 0)
	{
		error(XorStr("Xenos64"));
	}
	else if (FindProcessId(s2ws("Cheat Engine.exe")) != 0)
	{
		error(XorStr("Cheat Engine"));
	}
	else if (FindProcessId(s2ws("HTTP Debugger Windows Service (32 bit).exe")) != 0)
	{
		error(XorStr("HTTP Debugger"));
	}
	else if (FindProcessId(s2ws("KsDumper.exe")) != 0)
	{
		error(XorStr("KsDumper"));
	}
	else if (FindProcessId(s2ws("x64dbg.exe")) != 0)
	{
		error(XorStr("x64DBG"));
	}
}

void titledetect()
{
	HWND window;
	window = FindWindow(0, XorStr((L"IDA: Quick start")).c_str());
	if (window)
	{
		error(XorStr("IDA"));
	}

	window = FindWindow(0, XorStr((L"Memory Viewer")).c_str());
	if (window)
	{
		error(XorStr("Cheat Engine"));
	}

	window = FindWindow(0, XorStr((L"Process List")).c_str());
	if (window)
	{
		error(XorStr("Cheat Engine"));
	}

	window = FindWindow(0, XorStr((L"KsDumper")).c_str());
	if (window)
	{
		error(XorStr("KsDumper"));
	}
}

void driverdetect()
{
	const TCHAR* devices[] = {
_T("\\\\.\\NiGgEr"),
_T("\\\\.\\KsDumper")
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		if (hFile != INVALID_HANDLE_VALUE) {
			system(XorStr("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul").c_str());
			exit(0);
		}
		else
		{

		}
	}
}

void error(std::string msg)
{
	system(("START CMD /C \"COLOR C && TITLE Protection && ECHO INFO: ERROR: " + msg + " Detected. Please close and try again. && TIMEOUT 10 >nul").c_str());
	exit(0);
}

void debug()
{
	while (running)
	{
		killdbg();
		exedetect();
		titledetect();
		driverdetect();
	}
}

void killdbg()
{
	system(XorStr("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1").c_str());
	system(XorStr("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1").c_str());
	system(XorStr("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
	system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());
}

static std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[25];

	strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

	return std::string(buffer);
}








