#include"AntiDebug.h"
#include"encrypt.h"
#include"pe.h"
#include<stdio.h>

#pragma comment (lib,"user32.lib")

#pragma warning(disable:4996)


DWORD oldMessageBox;

typedef int (WINAPI *MessageBoxType)(HWND, LPCWSTR, LPCWSTR, UINT);

VOID DebugPresent(BOOL bPresent)
{
	if (bPresent == TRUE)
	{
		printf_s("The Debugger is Prohibited\n");
		exit(0);
	}
}

WCHAR* flag = (WCHAR*)malloc(256 * sizeof(WCHAR));
WCHAR* pos = flag - 0x500;
int unknown = (int)wcscpy(flag, L"flag{123456789}");


int WINAPI WkMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	((MessageBoxType)oldMessageBox)(hWnd,lpText,lpCaption,uType);

	wcscpy((WCHAR*)(pos + 0x500 + 0x05), L"753951}");
	return true;
}

int main()
{
	//CheckDebuggerByPEB(DebugPresent);
	oldMessageBox = FindFuncInIATM((DWORD)GetModuleHandle(NULL), "User32.dll", "MessageBoxW", (DWORD)WkMessageBoxW);
	if (oldMessageBox == FALSE)
		return FALSE;
	//CheckDebuggerBySEH(DebugPresent);
	//CheckDebuggerByName(DebugPresent);
	MessageBox(NULL, flag,L"good", NULL);
	system("pause");
	return 0;
}