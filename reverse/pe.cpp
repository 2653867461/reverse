#include"pe.h"

#pragma warning(disable:4996)

DWORD FindFuncInIATM(DWORD hModule, const char* moduleName, const char* funcName, DWORD newAddress)
{
	DWORD oldProtect = 0;
	DWORD address = hModule;
	if (*PTR_ADD(WORD*, hModule, 0) != 0x5A4D)
		return NULL;
	address += *PTR_ADD(LONG*, hModule, 0x3c);
	if (*PTR_ADD(DWORD*, address, 0) != 0x4550)
		return NULL;
	address = hModule + *PTR_ADD(DWORD*, address, 0x80);

	for (IMAGE_IMPORT_DESCRIPTOR* lpImport = (IMAGE_IMPORT_DESCRIPTOR*)address; lpImport->Name != 0; ++lpImport)
	{
		if (strcmpi((char*)(lpImport->Name+hModule), moduleName) != 0)
			continue;

		DWORD* lpName = (DWORD*)(lpImport->OriginalFirstThunk+ hModule);
		for (int i = 0; *lpName != 0; ++lpName, ++i)
		{
			if (!(*lpName & IMAGE_ORDINAL_FLAG))
			{
				if (strcmpi((char*)(*lpName+hModule+2), funcName) == 0)
				{
					BOOL bResult = VirtualProtect(&((DWORD*)(lpImport->FirstThunk + hModule))[i], 4, PAGE_EXECUTE_READWRITE, &oldProtect);
					address = ((DWORD*)(lpImport->FirstThunk+hModule))[i];
					((DWORD*)(lpImport->FirstThunk + hModule))[i] = newAddress;
					return address;
				}
			}
		}
	}
	return NULL;
}