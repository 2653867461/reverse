#pragma once

#include<Windows.h>
#include<tchar.h>
#include<winternl.h>

#pragma comment (lib,"ntdll.lib")

#define PTR_ADD(type,ptr,value)	((type)(((DWORD)ptr)+(value)))

static const WCHAR* DEBUGGER_NAME[] = { L"VsDebugConsole.exe",L"dbgx.shell.exe",L"ida.exe",L"x64dbg.exe",L"x32dbg.exe",L"ollydbg.exe" };
static const int DEBUGGER_NUM = 5;

typedef VOID(*DebuggerHandlerFunc)(BOOL);

static DebuggerHandlerFunc gHandlerFunc = NULL;

UCHAR CheckDebuggerByPEB(DebuggerHandlerFunc HandlerFunc= NULL);
BOOL CheckDebuggerBySEH(DebuggerHandlerFunc HandlerFunc= NULL);
BOOL CheckDebuggerByVEH(DebuggerHandlerFunc HandlerFunc= NULL);
BOOL CheckDebuggerByName(DebuggerHandlerFunc HandlerFunc= NULL);