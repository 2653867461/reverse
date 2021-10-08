#include"AntiDebug.h"

UCHAR CheckDebuggerByPEB(DebuggerHandlerFunc HandlerFunc)
{
UCHAR IsDebug = FALSE;
_asm {
	push eax;
	mov eax, fs: [0x30] ;
	mov al, [eax + 0x02];
	mov IsDebug, al;
	pop eax;
}
if (HandlerFunc != NULL)
HandlerFunc(IsDebug);
return IsDebug;
}

BOOL CheckDebuggerByName(DebuggerHandlerFunc HandlerFunc)
{
	SYSTEM_PROCESS_INFORMATION* lpProcessInfo = NULL, * lpBuffer = NULL;
	ULONG dwInfoSize = 0, dwNextOffset = 0;
	WCHAR* lpProcessName = NULL;
	BOOL bResult = FALSE;
	WCHAR lpsuccessfulInfo[256] = { 0 };
	NTSTATUS NtResult = 0;
	HANDLE hHeap = NULL;
	__try
	{
		hHeap = GetProcessHeap();

		if (hHeap == NULL)
			__leave;

		NtResult = NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &dwInfoSize);
	
		lpProcessInfo = (SYSTEM_PROCESS_INFORMATION*)HeapAlloc(hHeap, LMEM_FIXED | LMEM_ZEROINIT, dwInfoSize);

		lpBuffer = lpProcessInfo;
		if (lpProcessInfo == NULL)
			__leave;

		NtResult = NtQuerySystemInformation(SystemProcessInformation, lpProcessInfo, dwInfoSize, &dwInfoSize);

		if (!NT_SUCCESS(NtResult))
			__leave;

		do
		{
			dwNextOffset = lpProcessInfo->NextEntryOffset;
			lpProcessName = lpProcessInfo->ImageName.Buffer;

			if (lpProcessName != NULL)
			{
				for (int i = 0; i < DEBUGGER_NUM; ++i)
					if (_wcsicmp(lpProcessName, DEBUGGER_NAME[i]) == 0)
						bResult = TRUE;					
			}

			lpProcessInfo = PTR_ADD(SYSTEM_PROCESS_INFORMATION*, lpProcessInfo, dwNextOffset);
		} while (dwNextOffset != 0);
	}
	__finally {
		if (lpBuffer != NULL)
			HeapFree(hHeap, NULL, lpBuffer);

		//if (GetLastError() != 0)
			//_tprintf_s(L"Get Process Information failed ;errorCode %d \n", GetLastError());
	}
	if (HandlerFunc != NULL)
		HandlerFunc(bResult);
	return bResult;
}

LONG SehFilter(PEXCEPTION_POINTERS pExcepInfo)
{
	if (pExcepInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
		return EXCEPTION_EXECUTE_HANDLER;
	else
		return EXCEPTION_CONTINUE_SEARCH;
}

BOOL CheckDebuggerBySEH(DebuggerHandlerFunc HandlerFunc)
{
	BOOL bResult = TRUE;
	__try{
		_asm {
			int 3;
		}
	}
	__except(SehFilter(GetExceptionInformation()))
	{
		bResult = FALSE;
	}
	if (HandlerFunc != NULL)
		HandlerFunc(bResult);
	return bResult;
}

LONG NTAPI VehHandler(EXCEPTION_POINTERS* pExcepInfo)
{
	if (pExcepInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		if (gHandlerFunc != NULL)
			gHandlerFunc(TRUE);

		return EXCEPTION_EXECUTE_HANDLER;
	}
	else
		return EXCEPTION_CONTINUE_SEARCH;
}

BOOL CheckDebuggerByVEH(DebuggerHandlerFunc HandlerFunc)
{
	BOOL bResult = TRUE;
	LPVOID pVEH = AddVectoredExceptionHandler(TRUE, VehHandler);
	if (pVEH == NULL)
	{
		_tprintf_s(L"register veh failed\n");
		return false;
	}
	_asm { 
		int 3; 
	}
	RemoveVectoredContinueHandler(pVEH);
	return bResult;
}