#include <Windows.h>
#include <stdio.h>
	
typedef void (*FunctionAddressPtr)();

int ExceptionFilter(PEXCEPTION_POINTERS exceptionPointer, DWORD baseAddress) {
	printf("Exception Code: 0x%04x\n", exceptionPointer->ExceptionRecord->ExceptionCode);
	printf("Exception Address: 0x%04x\n", exceptionPointer->ExceptionRecord->ExceptionAddress);
	printf("Exception RVA: 0x%04x\n", (DWORD)exceptionPointer->ExceptionRecord->ExceptionAddress - baseAddress);
	if (exceptionPointer->ExceptionRecord->ExceptionFlags) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	else {
		return EXCEPTION_EXECUTE_HANDLER;
	}
}

PIMAGE_NT_HEADERS GetPEHeader(DWORD baseAddress) {
	PIMAGE_DOS_HEADER dosHeader = NULL;
	PIMAGE_NT_HEADERS peHeader = NULL;

	if (baseAddress){
		dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
		peHeader = (PIMAGE_NT_HEADERS)(baseAddress + (DWORD)dosHeader->e_lfanew);
	}
	
	return peHeader;
}

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(DWORD baseAddress) {
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

PIMAGE_SECTION_HEADER GetSectionHeader(DWORD baseAddress, DWORD rva) {
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

LPVOID RVAToFilePtr(DWORD baseAddress, DWORD rva) {
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

VOID PrintBasicHeaderInfo(DWORD baseAddress) {
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

DWORD MapFileView(PCHAR inputDll) {
	HANDLE hFile = NULL;
	HANDLE hFileMap = NULL;
	LPVOID fileMapPointer = NULL;
	DWORD baseAddress = 0;

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
		baseAddress = (DWORD)fileMapPointer;
	}

	return baseAddress;
}

BOOL Is32Bit(DWORD baseAddress) {
	PIMAGE_NT_HEADERS peHeader = NULL;
	
	peHeader = GetPEHeader(baseAddress);

	if (peHeader && *((char*)(&peHeader->Signature) + 4) == 'L') {
		return TRUE;
	}
	
	return FALSE;
}

BOOL IsReflectiveDll(DWORD baseAddress, __out FunctionAddressPtr* reflectiveRoutineAddr) {
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

	if (dataDirectory->VirtualAddress) {
		exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAToFilePtr(baseAddress, dataDirectory->VirtualAddress);

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

VOID ExecReflectiveDll(DWORD baseAddress, FunctionAddressPtr reflectiveRoutineAddr) {

	if (reflectiveRoutineAddr) {
		printf("Address: 0x%04x", reflectiveRoutineAddr);
		__try {
			reflectiveRoutineAddr();

			__asm {
				push 0x0
				push 0x4
				push baseAddress
				call eax
			}
		}
		__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {
		}
	}

	UnmapViewOfFile((LPCVOID)baseAddress);
}

VOID ExecExportsByName(HANDLE dllHandle) {
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
	PDWORD ENT = NULL;
	DWORD baseAddress = 0;
	FunctionAddressPtr functionAddress = NULL;

	baseAddress = (DWORD)dllHandle;
	exportDirectory = GetExportDirectory(baseAddress);

	if (exportDirectory == NULL) {
		return;
	}

	ENT = baseAddress + exportDirectory->AddressOfNames;
	printf("Calling 0x%04x exports via Name\n\n", exportDirectory->NumberOfNames);

	for (unsigned int i = 1; i <= exportDirectory->NumberOfNames; i++) {
		printf("%d. Export routine [%s] ", i, baseAddress + *ENT);
		functionAddress = (FunctionAddressPtr)GetProcAddress(dllHandle, (LPCSTR)(baseAddress + *ENT));
		if (functionAddress) {
			printf("Address: 0x%04x\n", functionAddress);

			__try {
				functionAddress();
			}
			__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {
			}
		}
		else {
			printf("Address: NULL\n");
		}
		ENT++;
	}
}

VOID ExecExportsByOrdinal(HANDLE dllHandle) {
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
	PWORD EOT = NULL;
	DWORD baseAddress = 0;
	FunctionAddressPtr functionAddress = NULL;

	baseAddress = (DWORD)dllHandle;
	exportDirectory = GetExportDirectory(baseAddress);

	if (exportDirectory == NULL) {
		return;
	}

	EOT = baseAddress + exportDirectory->AddressOfNameOrdinals;
	printf("Calling 0x%04x exports via Ordinal\n\n", exportDirectory->NumberOfNames);

	for (unsigned int i = 1; i <= exportDirectory->NumberOfNames; i++) {
		printf("%d. Export routine ordinal [0x%02x] ", i, (WORD)(*EOT + exportDirectory->Base));
		functionAddress = (FunctionAddressPtr)GetProcAddress(dllHandle, MAKEINTRESOURCE((WORD)(*EOT + exportDirectory->Base)));
		if (functionAddress) {
			printf("Address: 0x%04x\n", functionAddress);

			__try {
				functionAddress();
			}
			__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {

			}
		}
		else {
			printf("Address: NULL\n");
		}
		EOT++;
	}
}

VOID ExecExportsByAddressTable(HANDLE dllHandle) {
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;
	PDWORD EFT = NULL;
	DWORD baseAddress = 0;
	FunctionAddressPtr functionAddress = NULL;

	baseAddress = (DWORD)dllHandle;
	exportDirectory = GetExportDirectory(baseAddress);

	if (exportDirectory == NULL) {
		return;
	}

	EFT = baseAddress + exportDirectory->AddressOfFunctions;
	printf("Calling 0x%04x exports via FailSafe\n", exportDirectory->NumberOfFunctions);

	for (unsigned int i = 1; i <= exportDirectory->NumberOfFunctions; i++) {
		if (*EFT) {
			functionAddress = (FunctionAddressPtr)(baseAddress + *EFT);
			printf("%d. Address: 0x%04x\n", i, functionAddress);

			__try {
				functionAddress();
			}
			__except (ExceptionFilter(GetExceptionInformation(), baseAddress)) {
			}
		}
		else {
			printf("%d. Skipped\n", i);
		}
		EFT++;
	}
}

VOID ExecDll(PCHAR inputDll) {
	HMODULE dllHandle = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

	dllHandle = LoadLibraryA(inputDll);

	PrintBasicHeaderInfo((DWORD)dllHandle);
	
	exportDirectory = GetExportDirectory((DWORD)dllHandle);

	if (exportDirectory && exportDirectory->NumberOfFunctions) {
		printf("Export directory Number of Functions : 0x%04x\n", exportDirectory->NumberOfFunctions);
		printf("Export directory Number of Exports via Name: 0x%04x\n\n", exportDirectory->NumberOfNames);
		if (exportDirectory->NumberOfFunctions - exportDirectory->NumberOfNames) {
			ExecExportsByAddressTable(dllHandle);
		}
		else {
			if (exportDirectory->AddressOfNames && exportDirectory->AddressOfNameOrdinals) {
				ExecExportsByName(dllHandle);
			}
			else if (exportDirectory->AddressOfNameOrdinals) {
				ExecExportsByOrdinal(dllHandle);
			}
			else {
				ExecExportsByAddressTable(dllHandle);
			}
		}
	}

	FreeLibrary(dllHandle);
}

int main(int argc, char **argv) {
	DWORD baseAddress = 0;
	FunctionAddressPtr reflectiveRoutineAddr = NULL;

	if (argc == 2) {

		printf("Input Dll: %s\n", argv[1]);
		baseAddress = MapFileView(argv[1]);

		if (baseAddress) {
			if (Is32Bit(baseAddress)) {
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
				printf("Only 32-bit dll supported !!\n");
			}
		}
	}
	else {
		printf("[USAGE]: Dlluser.exe <dll_path>\n");
	}

	printf("All done!!. Press any key to exit.");
	getchar();
	return 0;
}
