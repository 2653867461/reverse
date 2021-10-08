#pragma once

#include<Windows.h>
#define PTR_ADD(type,ptr,value)	((type)(((DWORD)ptr)+(value)))

DWORD FindFuncInIATM(DWORD hModule,const char* moduleName,const char* funcName, DWORD newAddress);