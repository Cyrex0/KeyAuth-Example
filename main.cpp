#include <iostream>
#include "api/KeyAuth.hpp"
#include "xorstr.hpp"
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
using namespace KeyAuth;

/*
*
*
* WATCH THIS VIDEO FOR SETUP TUTORIAL: https://youtube.com/watch?v=uJ0Umy_C6Fg
* DO NOT CONTACT DISMAIL WITHOUT WATCHING VIDEO FIRST
*
*/

std::string name = ("");
std::string ownerid = ("");
std::string secret = ("");
std::string version = ("1.0");

api KeyAuthApp(name, ownerid, secret, version);


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

int main()
{
	SetConsoleTitleA(XorStr("Loader").c_str());
	std::cout << XorStr("\n\n Connecting..");
	KeyAuthApp.init();
	system(XorStr("cls").c_str());
	
	std::cout << XorStr("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

	int option;
	std::string username;
	std::string password;
	std::string key;

	std::cin >> option;
	switch (option)
	{
		case 1:
			std::cout << XorStr("\n\n Enter username: ");
			std::cin >> username;
			std::cout << XorStr("\n Enter password: ");
			std::cin >> password;
			KeyAuthApp.login(username, password);
			break;
		case 2:
			std::cout << XorStr("\n\n Enter username: ");
			std::cin >> username;
			std::cout << XorStr("\n Enter password: ");
			std::cin >> password;
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.regstr(username,password,key);
			break;
		case 3:
			std::cout << XorStr("\n\n Enter username: ");
			std::cin >> username;
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.upgrade(username, key);
			break;
		case 4:
			std::cout << XorStr("\n Enter license: ");
			std::cin >> key;
			KeyAuthApp.license(key);
			break;
		default:
			std::cout << XorStr("\n\n Status: Failure: Invalid Selection");
			Sleep(3000);
			exit(0);
	}

	std::vector<std::uint8_t> bytes = KeyAuthApp.download("123456"); // replace 123456 with the fileid of the file you uploaded to KeyAuth that you want to run through RunPE

	HWND ConsWind = GetConsoleWindow();
	// ShowWindow(ConsWind, 0);
	DWORD dwRet = 0;

	PROCESS_INFORMATION stPI;
	ZeroMemory(&stPI, sizeof stPI);
	STARTUPINFO stSI;
	ZeroMemory(&stSI, sizeof stSI);
	WCHAR szArgs[] = L"";
	if (!runPE64(
		&stPI,
		&stSI,
		reinterpret_cast<LPVOID>(bytes.data()),
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

	// Sleep(-1); // this is to keep your application open for test purposes. it pauses your application forever, remove this when you want.
}
