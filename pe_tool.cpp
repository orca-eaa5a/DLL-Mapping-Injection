#include <Windows.h>
#include "nt_apis.h"

#pragma once

PVOID GetProcessPebBase(_In_ HANDLE hProc){
	/* Read Process PEB Base Address using Process Handle */
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	LPNTQUERYINFORMATIONPROCESS lpNtQueryInformationProcess = (LPNTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION pbi;
	DWORD dwPBI;
	lpNtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &dwPBI);

	return pbi.PebBaseAddress;
}

PEB* GetProcessPEB(_In_ HANDLE hProc){
	/* Read Process PEB using Process Handle */
	DWORD dwNumberOfBytesToRead;
	PVOID peb_base = GetProcessPebBase(hProc);
	PEB* pPeb = (PEB*)calloc(1, sizeof(PEB));
	if(ReadProcessMemory(hProc, peb_base, pPeb, sizeof(PEB), &dwNumberOfBytesToRead)) return pPeb;
	else return NULL;
}

LPVOID GetProcessImageBase(_In_ HANDLE hProc){
	/* Read Process ImageBase Address using Process Handle */
	PEB* pPeb = GetProcessPEB(hProc);
	if(pPeb == NULL){
		OutputDebugString(L"GetProcessImageBase [ GetProcessPEB ]");
		return NULL;
	}

	LPVOID proc_img_base = pPeb->ImageBaseAddress;
	free(pPeb);

	return proc_img_base;
}

BYTE* GetPEHeadersBinary(_In_ HANDLE hProc){
	DWORD nt_hdr_start_offset = 0;
	DWORD sizeOfPEHeaders;
	DWORD numberOfBytesRead = 0;
	LPVOID img_base = GetProcessImageBase(hProc);
	BYTE* dos_hdr = (BYTE*)calloc(sizeof(IMAGE_DOS_HEADER), sizeof(BYTE));
	if(!ReadProcessMemory(hProc, img_base, dos_hdr, sizeof(IMAGE_DOS_HEADER), &numberOfBytesRead)){
		OutputDebugString(L"GetSizeOfProcessImage [ ReadProcessMemory [1] ]");
		exit(-1);
	}
	nt_hdr_start_offset = ((PIMAGE_DOS_HEADER)dos_hdr)->e_lfanew;
	free(dos_hdr);
#ifdef _WIN64
	sizeOfPEHeaders = nt_hdr_start_offset + sizeof(IMAGE_NT_HEADERS64);
#else
	sizeOfPEHeaders = nt_hdr_start_offset + sizeof(IMAGE_NT_HEADERS32);
#endif

	BYTE* pe_hdr = (BYTE*)calloc(sizeOfPEHeaders, sizeof(BYTE));
	if(!ReadProcessMemory(hProc, img_base, pe_hdr, sizeOfPEHeaders, &numberOfBytesRead)){
		OutputDebugString(L"GetSizeOfProcessImage [ ReadProcessMemory [2] ]");
		exit(-1);
	}

	return pe_hdr;
}

PIMAGE_DOS_HEADER GetImageDosHeader(_In_ BYTE* pe_file){
	/* Get IMAGE_DOS_HEADER FROM PE File or Image */
	return (PIMAGE_DOS_HEADER)pe_file;
}

PIMAGE_NT_HEADERS32 GetImageNtHeader32(_In_ BYTE* pe_file){
	/* Get IMAGE_NT_HEADERS32 FROM PE File or Image */
	PIMAGE_DOS_HEADER pDos_hdr = GetImageDosHeader(pe_file);
	return (PIMAGE_NT_HEADERS32)(pe_file + pDos_hdr->e_lfanew);
}

PIMAGE_NT_HEADERS64 GetImageNtHeader64(_In_ BYTE* pe_file){
	/* Get IMAGE_NT_HEADERS64 FROM PE File or Image */
	PIMAGE_DOS_HEADER pDos_hdr = GetImageDosHeader(pe_file);
	return (PIMAGE_NT_HEADERS64)(pe_file + pDos_hdr->e_lfanew);
}

PIMAGE_NT_HEADERS GetImageNtHeader(_In_ BYTE* pe_file){
	/* Get IMAGE_NT_HEADERS FROM PE File or Image */
#ifdef _WIN64
	return GetImageNtHeader64(pe_file);
#else
	return GetImageNtHeader32(pe_file);
#endif
}

void GetImageNtHeader32(_In_ HANDLE hProc, _Out_ PIMAGE_NT_HEADERS32 pNt_hdr32){
	BYTE* pe_hdr = GetPEHeadersBinary(hProc);
	DWORD nt_hdr_start_offset = ((PIMAGE_DOS_HEADER)pe_hdr)->e_lfanew;
	memcpy(pNt_hdr32, (pe_hdr+nt_hdr_start_offset), sizeof(IMAGE_NT_HEADERS32));
	free(pe_hdr);

	return;
}

void GetImageNtHeader64(_In_ HANDLE hProc, _Out_ PIMAGE_NT_HEADERS64 pNt_hdr64){
	BYTE* pe_hdr = GetPEHeadersBinary(hProc);
	DWORD nt_hdr_start_offset = ((PIMAGE_DOS_HEADER)pe_hdr)->e_lfanew;
	memcpy(pNt_hdr64, (pe_hdr+nt_hdr_start_offset), sizeof(IMAGE_NT_HEADERS64));
	free(pe_hdr);

	return;
}

void GetImageNtHeader(_In_ HANDLE hProc, _Out_ PIMAGE_NT_HEADERS pNt_hdr){
	BYTE* pe_hdr = GetPEHeadersBinary(hProc);
	DWORD nt_hdr_start_offset = ((PIMAGE_DOS_HEADER)pe_hdr)->e_lfanew;
#ifdef _WIN64
	GetImageNtHeader64(hProc, pNt_hdr);
#else
	GetImageNtHeader32(hProc, pNt_hdr);
#endif
	return;
}

PIMAGE_OPTIONAL_HEADER32 GetImageOptionalHeader32(_In_ BYTE* pe_file){
	/* Get IMAGE_OPTIONAL_HEADER32 FROM PE File or Image */
	PIMAGE_NT_HEADERS32 pNt_hdr32 = GetImageNtHeader32(pe_file);
	return (PIMAGE_OPTIONAL_HEADER32)((BYTE*)&pNt_hdr32->OptionalHeader);
}

PIMAGE_OPTIONAL_HEADER64 GetImageOptionalHeader64(_In_ BYTE* pe_file){
	/* Get IMAGE_OPTIONAL_HEADER64 FROM PE File or Image */
	PIMAGE_NT_HEADERS64 pNt_hdr64 = GetImageNtHeader64(pe_file);
	return (PIMAGE_OPTIONAL_HEADER64)((BYTE*)&pNt_hdr64->OptionalHeader);
}

PIMAGE_OPTIONAL_HEADER GetImageOptionalHeader(_In_ BYTE* pe_file){
	/* Get IMAGE_OPTIONAL_HEADER FROM PE File or Image */
#ifdef _WIN64
	return GetImageOptionalHeader64(pe_file);
#else	
	return GetImageOptionalHeader32(pe_file);
#endif
}

PIMAGE_FILE_HEADER GetImageFileHeader(_In_ BYTE* pe_file){
	/* Get IMAGE_FILE_HEADER FROM PE File or Image */
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 pNt_hdr64 = GetImageNtHeader64(pe_file);
	return (PIMAGE_FILE_HEADER)&(pNt_hdr64->FileHeader);
#else
	PIMAGE_NT_HEADERS32 pNt_hdr32 = GetImageNtHeader32(pe_file);
	return (PIMAGE_FILE_HEADER)&(pNt_hdr32->FileHeader);
#endif;
}

DWORD GetNumberOfSections(_In_ BYTE* pe_file){
	/* Get Number Of Sections FROM PE File or Image */
	PIMAGE_FILE_HEADER pImg_file_hdr = GetImageFileHeader(pe_file);
	return pImg_file_hdr->NumberOfSections;
}

PIMAGE_SECTION_HEADER* GetSectionHeaders(_In_ BYTE* pe_file){
	/* Get IMAGE_OPTIONAL_HEADER FROM PE File or Image */
	DWORD numberOfSections = GetNumberOfSections(pe_file);
	PIMAGE_NT_HEADERS nt_hdr = GetImageNtHeader(pe_file);
	PIMAGE_SECTION_HEADER* section_list = (PIMAGE_SECTION_HEADER*)calloc(numberOfSections, sizeof(PIMAGE_SECTION_HEADER));
	for(int i = 0; numberOfSections > i; i++){
		PIMAGE_SECTION_HEADER pCur_sec_hdr = (IMAGE_SECTION_HEADER*)((BYTE*)&nt_hdr->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER) + sizeof(IMAGE_SECTION_HEADER)*(i));
		section_list[i] = pCur_sec_hdr;
	}

	return section_list;
}

PIMAGE_SECTION_HEADER GetSectionHeaderByName(_In_ BYTE* pe_file, _In_ const char* name){
	DWORD numberOfSections = GetNumberOfSections(pe_file);
	PIMAGE_SECTION_HEADER* section_headers = GetSectionHeaders(pe_file);
	PIMAGE_SECTION_HEADER target_section = NULL;
	for(int i = 0; numberOfSections > i; i++){
		BYTE* cur_sec_name = section_headers[i]->Name;
		if(strcmp((const char*)cur_sec_name, name) == 0){
			//memcpy(target_section, section_headers[i], sizeof(PIMAGE_SECTION_HEADER));
			target_section = section_headers[i];
			break;
		}
	}
	free(section_headers);
	return target_section;
}

LPVOID GetSectionBaseRAW(_In_ BYTE* pe_file, _In_ const char* name){
	PIMAGE_SECTION_HEADER section = GetSectionHeaderByName(pe_file, name);
	if(section == NULL){
		OutputDebugString(L"GetRawSectionBase [ GetSectionHeaderByName ]");
		return NULL;
	}
	
	return (LPVOID)section->PointerToRawData;
}

LPVOID GetSectionBaseRVA(_In_ BYTE* pe_file, _In_ const char* name){
	PIMAGE_SECTION_HEADER section = GetSectionHeaderByName(pe_file, name);
	if(section == NULL){
		OutputDebugString(L"GetRawSectionBase [ GetSectionHeaderByName ]");
		return NULL;
	}

	return (LPVOID)section->VirtualAddress;
}

DWORD GetSizeOfSection(_In_ BYTE* pe_file, _In_ const char* name){
	PIMAGE_SECTION_HEADER section = GetSectionHeaderByName(pe_file, name);
	if(section == NULL){
		OutputDebugString(L"GetRawSectionBase [ GetSectionHeaderByName ]");
		return NULL;
	}

	return section->SizeOfRawData;
}

PIMAGE_DATA_DIRECTORY GetDataDirectory(_In_ BYTE* pe_file, _In_ int type){
	PIMAGE_OPTIONAL_HEADER img_opt_hdr = GetImageOptionalHeader(pe_file);
	PIMAGE_DATA_DIRECTORY pImg_data_dir = &img_opt_hdr->DataDirectory[type];
	img_opt_hdr->DataDirectory;

	return pImg_data_dir;
}

BYTE* ConvertToImage(_In_ BYTE* pe_bin){
	PIMAGE_DOS_HEADER pDos_hdr = GetImageDosHeader(pe_bin);
	PIMAGE_NT_HEADERS pNt_hdr = GetImageNtHeader(pe_bin);
	PIMAGE_SECTION_HEADER* section_hdrs = GetSectionHeaders(pe_bin);
	DWORD szOfImg = pNt_hdr->OptionalHeader.SizeOfImage;
	BYTE* pe_img = (BYTE*)calloc(szOfImg, sizeof(BYTE));
	DWORD numberOfSection = GetNumberOfSections(pe_bin);
	memmove(pe_img, pe_bin, pNt_hdr->OptionalHeader.SizeOfHeaders);
	for(int i = 0; numberOfSection > i; i++){
		DWORD section_raw = section_hdrs[i]->PointerToRawData;
		DWORD section_rva = section_hdrs[i]->VirtualAddress;
		DWORD size_of_section = section_hdrs[i]->SizeOfRawData;
		memcpy((pe_img+section_rva), (pe_bin+section_raw), size_of_section);
	}
	free(section_hdrs);
	return pe_img;
}

void RelocatePEImage(_Inout_ BYTE* old_pe_img, _In_ DWORD new_pe_img_base){
	typedef struct BASE_RELOCATION_BLOCK {
		unsigned long PageAddress;
		unsigned long BlockSize;
	} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

	typedef struct BASE_RELOCATION_ENTRY {
		unsigned short Offset : 12;
		unsigned short Type : 4;
	} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

	PIMAGE_NT_HEADERS nt_hdr = GetImageNtHeader(old_pe_img);
	PIMAGE_SECTION_HEADER pSec_hdr = GetSectionHeaderByName(old_pe_img, ".reloc");
	PIMAGE_DATA_DIRECTORY reloc_directory = GetDataDirectory(old_pe_img, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	DWORD origin_img_base = nt_hdr->OptionalHeader.ImageBase;
	DWORD reloc_delta = new_pe_img_base - origin_img_base;
	DWORD reloc_sec_rva = 0;
	DWORD reloc_dir_rva = 0;
	DWORD number_of_reloc_entries = 0;
	DWORD block_offset = 0;
	BYTE* reloc_sec = NULL;

	memmove(&nt_hdr->OptionalHeader.ImageBase, &new_pe_img_base, sizeof(DWORD));
	reloc_sec_rva = pSec_hdr->VirtualAddress;
	reloc_dir_rva = reloc_directory->VirtualAddress;
	reloc_sec = (old_pe_img + reloc_sec_rva);
	if(!reloc_delta) return;
	while(reloc_directory->Size > block_offset){
		PBASE_RELOCATION_BLOCK pCur_reloc_block = (PBASE_RELOCATION_BLOCK)(reloc_sec + block_offset);
		PBASE_RELOCATION_ENTRY pStart_entry = (PBASE_RELOCATION_ENTRY)(reloc_sec + block_offset + sizeof(BASE_RELOCATION_BLOCK));
		number_of_reloc_entries = (pCur_reloc_block->BlockSize-sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		for(int idx = 0; number_of_reloc_entries > idx; idx++){
			PBASE_RELOCATION_ENTRY cur_reloc_entry = (PBASE_RELOCATION_ENTRY)((PVOID)((DWORD)pStart_entry+sizeof(BASE_RELOCATION_ENTRY)*idx));
			if(cur_reloc_entry->Type == 0) continue;
			DWORD reloc_rva = pCur_reloc_block->PageAddress + cur_reloc_entry->Offset;
			DWORD bf_reloc_addr = 0;
			memmove(&bf_reloc_addr, (old_pe_img + reloc_rva), sizeof(DWORD));
			DWORD aft_reloc_addr = (bf_reloc_addr + reloc_delta);
			memmove((old_pe_img+ reloc_rva), &aft_reloc_addr, sizeof(DWORD));
		}
		block_offset += pCur_reloc_block->BlockSize;
	}
	return;
}

void RelocatePEImage(_In_ BYTE* old_pe_img, _In_ DWORD new_pe_img_base, _Out_ BYTE* new_pe_img){
	typedef struct BASE_RELOCATION_BLOCK {
		unsigned long PageAddress;
		unsigned long BlockSize;
	} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

	typedef struct BASE_RELOCATION_ENTRY {
		unsigned short Offset : 12;
		unsigned short Type : 4;
	} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

	PIMAGE_DOS_HEADER dos_hdr = GetImageDosHeader(old_pe_img);
	PIMAGE_NT_HEADERS nt_hdr = GetImageNtHeader(old_pe_img);
	DWORD origin_img_base = nt_hdr->OptionalHeader.ImageBase;
	DWORD reloc_delta = new_pe_img_base - origin_img_base;
	PIMAGE_SECTION_HEADER pSec_hdr = GetSectionHeaderByName(old_pe_img, ".reloc");
	DWORD reloc_sec_rva = 0;
	DWORD reloc_dir_rva = 0;
	DWORD number_of_reloc_entries = 0;
	PIMAGE_DATA_DIRECTORY reloc_directory = GetDataDirectory(old_pe_img, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	memmove(&nt_hdr->OptionalHeader.ImageBase, &new_pe_img_base, sizeof(DWORD));
	memcpy(new_pe_img, old_pe_img, nt_hdr->OptionalHeader.SizeOfImage);
	memcpy((old_pe_img+dos_hdr->e_lfanew), nt_hdr, sizeof(IMAGE_NT_HEADERS));
	reloc_sec_rva = pSec_hdr->VirtualAddress;
	reloc_dir_rva = reloc_directory->VirtualAddress;
	BYTE* reloc_sec = (old_pe_img + reloc_sec_rva);
	DWORD block_offset = 0;
	if(!reloc_delta) return;
	while(reloc_directory->Size > block_offset){
		PBASE_RELOCATION_BLOCK pCur_reloc_block = (PBASE_RELOCATION_BLOCK)(reloc_sec + block_offset);
		PBASE_RELOCATION_ENTRY pStart_entry = (PBASE_RELOCATION_ENTRY)(reloc_sec + block_offset + sizeof(BASE_RELOCATION_BLOCK));
		number_of_reloc_entries = (pCur_reloc_block->BlockSize-sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		for(int idx = 0; number_of_reloc_entries > idx; idx++){
			PBASE_RELOCATION_ENTRY cur_reloc_entry = (PBASE_RELOCATION_ENTRY)((PVOID)((DWORD)pStart_entry+sizeof(BASE_RELOCATION_ENTRY)*idx));
			if(cur_reloc_entry->Type == 0) continue;
			DWORD reloc_rva = pCur_reloc_block->PageAddress + cur_reloc_entry->Offset;
			DWORD bf_reloc_addr = 0;
			memmove(&bf_reloc_addr, (old_pe_img + reloc_rva), sizeof(DWORD));
			DWORD aft_reloc_addr = (bf_reloc_addr + reloc_delta);
			memmove((new_pe_img+ reloc_rva), &aft_reloc_addr, sizeof(DWORD));
		}
		block_offset += pCur_reloc_block->BlockSize;
	}
}

bool UnmapProcessImageFromVAS(_In_ HANDLE hProc){
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	LPNTUNMAPVIEWOFSECTION lpNtUnMapViewOfSection = (LPNTUNMAPVIEWOFSECTION)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	LPVOID img_base = GetProcessImageBase(hProc);
	NTSTATUS stat = (NTSTATUS)lpNtUnMapViewOfSection(hProc, img_base);
	if(NT_SUCCESS(stat)){
		return true;
	}
	else {
		OutputDebugString(L"UnmapProcessImageFromVAS [ NtUnMapViewOfSection ]");
		return false;
	}
}

DWORD GetSizeOfProcessImage(_In_ HANDLE hProc){
	BYTE* pe_bin = GetPEHeadersBinary(hProc);
	PIMAGE_NT_HEADERS nt_hdr = GetImageNtHeader(pe_bin);
	DWORD sizeOfImage = nt_hdr->OptionalHeader.SizeOfImage;
	free(pe_bin);

	return sizeOfImage;
}

BYTE* GetProcessImageBinary(_In_ HANDLE hProc){
	NTSTATUS stat = 0;
	DWORD numberOfBytesRead;
	DWORD sizeOfImg = GetSizeOfProcessImage(hProc);
	LPVOID img_base = GetProcessImageBase(hProc);
	BYTE* proc_img_bin = (BYTE*)calloc(sizeOfImg, sizeof(BYTE));
	if(!ReadProcessMemory(hProc, img_base, proc_img_bin, sizeOfImg, &numberOfBytesRead)){
		OutputDebugString(L"GetProcessImageBinary [ ReadprocessMemory ]");
		return NULL;
	}

	return proc_img_bin;
}