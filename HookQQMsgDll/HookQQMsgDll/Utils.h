#pragma once

#include <windows.h>

#define SYSTEM_VERSION_WIN9X	1
#define SYSTEM_VERSION_WIN2000	2
#define SYSTEM_VERSION_XP		3
#define SYSTEM_VERSION_VISTA	4
#define SYSTEM_VERSION_WIN7		5
#define SYSTEM_VERSION_WIN8		6
#define SYSTEM_VERSION_WIN10	7
#define SYSTEM_VERSION_UNKNOW	0


#define WRITE_LOG_ERROR_PACKET	1
#define WRITE_LOG_ERROR			2
#define WRITE_LOG_MSG			3
#define WRITE_LOG_NORMAL		4


unsigned int	__stdcall	GetApiAddrFromDll(unsigned int  pIdh, char* lpApiName, int iApiNameLen);

int __stdcall GetWindowsVersion();

int __stdcall WriteLog(char* Pack, int PackLen, DWORD dwFlag);

char* __stdcall ViolenceSearch(char Flag[], int FlagLen, char Address[], int TotalLen);

char* __stdcall ConvertUtf8ToGBK(char* strUtf8, char* strPlat);