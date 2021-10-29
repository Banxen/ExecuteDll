#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

typedef void (*FunctionAddressPtr)();

#ifdef _WIN64
	#define DWORD_32_64 DWORD64
    #define FORMAT_STR "0x%08llx"
#else
	#define DWORD_32_64 DWORD
	#define FORMAT_STR "0x%04x"
#endif

BOOL execViaRundll32 = FALSE;

int ExceptionFilter(PEXCEPTION_POINTERS exceptionPointer, DWORD_32_64 baseAddress) {
	printf("Exception Code: 0x%04x\n", exceptionPointer->ExceptionRecord->ExceptionCode);
	printf("Exception Address: " FORMAT_STR "\n", exceptionPointer->ExceptionRecord->ExceptionAddress);
	printf("Exception RVA: " FORMAT_STR "\n", (DWORD_32_64)exceptionPointer->ExceptionRecord->ExceptionAddress - baseAddress);
	
	if (exceptionPointer->ExceptionRecord->ExceptionFlags) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	else {
		return EXCEPTION_EXECUTE_HANDLER;
	}
}

PIMAGE_NT_HEADERS GetPEHeader(DWORD_32_64 baseAddress) {
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS peHeader = NULL;

	if (baseAddress){
		dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
		peHeader = (PIMAGE_NT_HEADERS)(baseAddress + (DWORD)dosHeader->e_lfanew);
	}
	
	return peHeader;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(DWORD_32_64 baseAddress) {
	PIMAGE_NT_HEADERS peHeader = NULL;
	PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

	peHeader = GetPEHeader(baseAddress);

	if (peHeader) {
		dataDirectory = &(peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		if (dataDirectory->VirtualAddress) {
			exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + dataDirectory->VirtualAddress);
		}
	}

	return exportDirectory;
}

PIMAGE_SECTION_HEADER GetSectionHeader(DWORD_32_64 baseAddress, DWORD rva) {
	PIMAGE_NT_HEADERS peHeader = NULL;
	PIMAGE_SECTION_HEADER sectionHeader = NULL;
	unsigned int nSections = 0;
	unsigned int index = 0;

	peHeader = GetPEHeader(baseAddress);

	if (peHeader == NULL) {
		return sectionHeader;
	}

	sectionHeader = IMAGE_FIRST_SECTION(peHeader);
	nSections = peHeader->FileHeader.NumberOfSections;

	for (index = 0; index < nSections; index++, sectionHeader++) {
		if (rva >= sectionHeader->VirtualAddress && rva < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)) {
			return sectionHeader;
		}
	}

	return NULL;
}

LPVOID RVAToFilePtr(DWORD_32_64 baseAddress, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = NULL;
	DWORD addressInBuffer = 0;
	DWORD addressInMem = 0;
	INT difference = 0;

	sectionHeader = (PIMAGE_SECTION_HEADER)GetSectionHeader(baseAddress, rva);

	if (sectionHeader) {
		addressInBuffer = sectionHeader->PointerToRawData;
		addressInMem = sectionHeader->VirtualAddress;
		difference = (INT)(rva - addressInMem);
		return((LPVOID)(baseAddress + addressInBuffer + (DWORD)difference));
	}

	return NULL;
}

VOID PrintBasicHeaderInfo(DWORD_32_64 baseAddress) {
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS peHeader = NULL;
		
	dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	peHeader = GetPEHeader(baseAddress);

	if (dosHeader && peHeader) {
		printf("Magic Number : 0x%04x\n", dosHeader->e_magic);
		printf("Offset to IMAGE_NT_HEADERS: 0x%04x\n", dosHeader->e_lfanew);

		printf("Signature IMAGE_NT_HEADERS: 0x%04x\n", peHeader->Signature);
		printf("No of sections: 0x%04x\n", peHeader->FileHeader.NumberOfSections);
		printf("Magic Number IMAGE_NT_HEADERS: 0x%04x\n", peHeader->OptionalHeader.Magic);
	}
}

DWORD_32_64 MapFileView(PCHAR inputDll) {
	HANDLE hFile = NULL;
	HANDLE hFileMap = NULL;
	LPVOID fileMapPointer = NULL;
	DWORD_32_64 baseAddress = 0;

	hFile = CreateFileA(inputDll, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hFile) {
		hFileMap = CreateFileMappingA(hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
	}
	if (hFileMap) {
		fileMapPointer = MapViewOfFile(hFileMap, FILE_MAP_EXECUTE | FILE_MAP_READ, 0, 0, 0);
	}
	if (fileMapPointer) {
		CloseHandle(hFileMap);
		CloseHandle(hFile);
		baseAddress = (DWORD_32_64)fileMapPointer;
	}

	return baseAddress;
}

#ifdef _WIN64

	BOOL Is64Bit(DWORD_32_64 baseAddress) {
		PIMAGE_NT_HEADERS peHeader = NULL;
	
		peHeader = GetPEHeader(baseAddress);

		if (peHeader && *((char*)(&peHeader->Signature) + 4) == 'L') {
			return FALSE;
		}
	
		return TRUE;
	}

#else

	BOOL Is32Bit(DWORD_32_64 baseAddress) {
		PIMAGE_NT_HEADERS peHeader = NULL;

		peHeader = GetPEHeader(baseAddress);

		if (peHeader && *((char*)(&peHeader->Signature) + 4) == 'L') {
			return TRUE;
		}

		return FALSE;
	}

#endif

BOOL IsReflectiveDll(DWORD_32_64 baseAddress, __out FunctionAddressPtr* reflectiveRoutineAddr) {
	PIMAGE_NT_HEADERS peHeader = NULL;
	PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
	PDWORD ENT = NULL;
	PDWORD EAT = NULL;

	peHeader = GetPEHeader(baseAddress);

	if (peHeader == NULL) {
		return FALSE;
	}

	dataDirectory = &(peHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	
	if (dataDirectory == NULL) {
		return FALSE;
	}

	if (dataDirectory->VirtualAddress) {
		exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAToFilePtr(baseAddress, dataDirectory->VirtualAddress);
		
		if (exportDirectory == NULL) {
			printf("Export directory seems outside the contained sections!!");
			return FALSE;
		}

		if (exportDirectory->AddressOfNames) {
			ENT = (PDWORD)RVAToFilePtr(baseAddress, exportDirectory->AddressOfNames);
			EAT = (PDWORD)RVAToFilePtr(baseAddress, exportDirectory->AddressOfFunctions);
			for (unsigned int i = 1; i <= exportDirectory->NumberOfNames; i++) {
				if (strstr((char *)RVAToFilePtr(baseAddress, *ENT), "ReflectiveLoader")) {
					*reflectiveRoutineAddr = (FunctionAddressPtr)RVAToFilePtr(baseAddress, *EAT);
					return TRUE;
				}
				EAT++;
				ENT++;
			}
		}
	}
	
	UnmapViewOfFile((LPCVOID)baseAddress);
	return FALSE;
}

VOID ExecReflectiveDll(DWORD_32_64 baseAddress, FunctionAddressPtr reflectiveRoutineAddr) {

	if (reflectiveRoutineAddr) {
		printf("Address: " FORMAT_STR "\n", reflectiveRoutineAddr);
		__try {
			reflectiveRoutineAddr();
			#ifdef _WIN64
				__nop();
				__nop();
				__nop();
				__nop();
				__nop();    // Need to be patched in binary or assembly
				__nop();
				__nop();
				__nop();
				__nop();
				__nop();
				__nop();
			#else
				__asm {
					push 0x0
					push 0x4
					push baseAddress
					call eax
				}
			#endif
		}
		__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {
		}
	}

	UnmapViewOfFile((LPCVOID)baseAddress);
}

VOID ExecExportByRundll32(LPSTR commandLine) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

VOID ExecExportsByName(HANDLE dllHandle) {
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
	PDWORD ENT = NULL;
	DWORD_32_64 baseAddress = 0;
	FunctionAddressPtr functionAddress = NULL;
	char commandLine[300];
	char dllName[256];

	baseAddress = (DWORD_32_64)dllHandle;
	GetModuleFileNameA(dllHandle, dllName, sizeof(dllName));
	exportDirectory = GetExportDirectory(baseAddress);

	if (exportDirectory == NULL) {
		return;
	}

	ENT = (PDWORD)(baseAddress + exportDirectory->AddressOfNames);
	printf("Calling 0x%04x exports via Name\n\n", exportDirectory->NumberOfNames);

	for (unsigned int i = 1; i <= exportDirectory->NumberOfNames; i++) {
		printf("%d. Export routine [%s] ", i, (char*)(baseAddress + *ENT));
		
		if (execViaRundll32) {
			wsprintfA(commandLine, "%s %s,%s", "rundll32.exe", dllName, baseAddress + *ENT);
			printf("\nCommandLine: %s\n", commandLine);
			ExecExportByRundll32(commandLine);
		}
		else {
			functionAddress = (FunctionAddressPtr)GetProcAddress(dllHandle, (LPCSTR)(baseAddress + *ENT));
			
			if (functionAddress) {
				printf("Address: " FORMAT_STR "\n", functionAddress);

				__try {
					functionAddress();
				}
				__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {
				}

			}
			else {
				printf("Address: NULL\n");
			}
		}

		Sleep(10);
		ENT++;
	}
}

VOID ExecExportsByOrdinal(HANDLE dllHandle) {
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
	PDWORD EFT = NULL;
	DWORD_32_64 baseAddress = 0;
	FunctionAddressPtr functionAddress = NULL;
	char commandLine[300];
	char dllName[256];

	baseAddress = (DWORD_32_64)dllHandle;
	GetModuleFileNameA(dllHandle, dllName, sizeof(dllName));
	exportDirectory = GetExportDirectory(baseAddress);

	if (exportDirectory == NULL) {
		return;
	}

	EFT = (PDWORD)(baseAddress + exportDirectory->AddressOfFunctions);
	printf("Calling 0x%04x exports via Ordinal\n\n", exportDirectory->NumberOfFunctions);

	for (unsigned int i = 0; i < exportDirectory->NumberOfFunctions; i++) {
		printf("%d. Export routine ordinal [0x%02x] ", i+1, (WORD)(i + exportDirectory->Base));
		if (*EFT) {
			if (execViaRundll32) {
				wsprintfA(commandLine, "%s %s,#%d", "rundll32.exe", dllName, (WORD)(i + exportDirectory->Base));
				printf("\nCommandLine: %s\n", commandLine);
				ExecExportByRundll32(commandLine);
			}
			else {
				functionAddress = (FunctionAddressPtr)GetProcAddress(dllHandle, MAKEINTRESOURCE((WORD)(i + exportDirectory->Base)));

				if (functionAddress) {
					printf("Address: " FORMAT_STR "\n", functionAddress);

					__try {
						functionAddress();
					}
					__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {
					}
					
				}
				else {
					printf("Address: NULL\n");
				}
			}
		}
		else {
			printf("\n");
		}

		Sleep(1000);
		EFT++;
	}
}


VOID ExecDll(PCHAR inputDll) {
	HMODULE dllHandle = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

	dllHandle = LoadLibraryA(inputDll);

	if (dllHandle == NULL) {
		return;
	}

	Sleep(10);

	PrintBasicHeaderInfo((DWORD_32_64)dllHandle);
	
	exportDirectory = GetExportDirectory((DWORD_32_64)dllHandle);

	if (exportDirectory && exportDirectory->NumberOfFunctions) {
		printf("Export directory Number of Functions : 0x%04x\n", exportDirectory->NumberOfFunctions);
		printf("Export directory Number of Exports via Name: 0x%04x\n\n", exportDirectory->NumberOfNames);
		if ((exportDirectory->NumberOfFunctions - exportDirectory->NumberOfNames) && exportDirectory->AddressOfFunctions) {
			ExecExportsByOrdinal(dllHandle);
		}
		else if (exportDirectory->AddressOfNames && exportDirectory->AddressOfNameOrdinals && exportDirectory->AddressOfFunctions) {
			ExecExportsByName(dllHandle);
		}
	}

	FreeLibrary(dllHandle);
	Sleep(10);
}

int main(int argc, char **argv) {
	DWORD_32_64 baseAddress = 0;
	FunctionAddressPtr reflectiveRoutineAddr = NULL;

	if (argc >= 2 && argc <=3) {

		if (argc == 3) {
			if (strcmp(argv[2], "--rundll32") == 0) {
				execViaRundll32 = TRUE;
			}
		}

		printf("Input Dll: %s\n", argv[1]);
		baseAddress = MapFileView(argv[1]);

		if (baseAddress) {
			if (
				#ifdef _WIN64 
					Is64Bit(baseAddress) 
				#else 
					Is32Bit(baseAddress)
				#endif
			) {
				if (IsReflectiveDll(baseAddress, &reflectiveRoutineAddr)) {
					PrintBasicHeaderInfo(baseAddress);
					printf("Reflective Dll Found. Unstable!! Only CobaltStrike dll where export name contains ReflectiveLoader is executed!!\n\n");
					ExecReflectiveDll(baseAddress, reflectiveRoutineAddr);
				}
				else {
					ExecDll(argv[1]);
				}
			}
			else {
				#ifdef _WIN64
					printf("Only 64-bit dll supported !!\n");
				#else
					printf("Only 32-bit dll supported !!\n");
				#endif	
			}
		}
	}
	else {
		printf("[USAGE]: ExecuteDll.exe <dll_path> [--rundll32]\n");
	}

	printf("All done!!. Press any key to exit.");
	getchar();
	return 0;
}
