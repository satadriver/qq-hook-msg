

#include <Windows.h>

#include <Lmwksta.h >

#include <Lmapibuf.h>

#include "Utils.h"

#include "HookQQMsgDll.h"

int __stdcall GetWindowsVersion()
{
	WKSTA_INFO_100* wkstaInfo = NULL;
	NET_API_STATUS netStatus = NetWkstaGetInfo(NULL, 100, (LPBYTE*)&wkstaInfo);
	if (netStatus == 0)
	{
		int iSystemVersion = 0;
		DWORD dwMajVer = wkstaInfo->wki100_ver_major;
		DWORD dwMinVer = wkstaInfo->wki100_ver_minor;
		DWORD dwVersion = (DWORD)MAKELONG(dwMinVer, dwMajVer);
		netStatus = NetApiBufferFree(wkstaInfo);

		iSystemVersion = 0;
		if (dwVersion < 0x50000)
		{
			iSystemVersion = SYSTEM_VERSION_WIN9X;
		}
		else if (dwVersion == 0x50000)
		{
			iSystemVersion = SYSTEM_VERSION_WIN2000;
		}
		else if (dwVersion > 0x50000 && dwVersion < 0x60000)
		{
			iSystemVersion = SYSTEM_VERSION_XP;
		}
		else if (dwVersion == 0x60000)
		{
			iSystemVersion = SYSTEM_VERSION_VISTA;
		}
		else if (dwVersion == 0x60001)
		{
			iSystemVersion = SYSTEM_VERSION_WIN7;
		}
		else if (dwVersion >= 0x60002 && dwVersion <= 0x60003)
		{
			iSystemVersion = SYSTEM_VERSION_WIN8;
		}
		else if (dwVersion >= 0x60003 || dwVersion >= 0x100000)
		{
#ifdef _DEBUG

			char szShowInfo[1024];
			int iRet = wsprintfA(szShowInfo, "win10 system version:%u.%u\r\n", dwMajVer, dwMinVer);
			WriteLog(szShowInfo, iRet, WRITE_LOG_NORMAL);
#endif
			iSystemVersion = SYSTEM_VERSION_WIN10;
		}
		else
		{
			iSystemVersion = SYSTEM_VERSION_UNKNOW;
		}
		return iSystemVersion;
	}

	return TRUE;
}


char* __stdcall ConvertUtf8ToGBK(char* strUtf8, char* strPlat)
{
	try
	{
		int len = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)strUtf8, -1, NULL, 0);
		wchar_t* wszGBK = new wchar_t[len];
		memset(wszGBK, 0, len);
		int iRet = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)strUtf8, -1, wszGBK, len);

		len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);

		iRet = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, strPlat, len, NULL, NULL);

		delete[] wszGBK;
		return strPlat;
	}
	catch (...)
	{
		WriteLog("ConvertUtf8ToGBK error\r\n", strlen("ConvertUtf8ToGBK error\r\n"), WRITE_LOG_ERROR);
		return FALSE;
	}
}


char* __stdcall ViolenceSearch(char Flag[], int FlagLen, char Address[], int TotalLen)
{
	try
	{
		for (int Cnt = 0; Cnt < TotalLen - FlagLen + 1; Cnt++)
		{
			if (memcmp(Flag, Address + Cnt, FlagLen) == 0)
			{
				return Address + Cnt + FlagLen;
			}
		}
		return FALSE;
	}
	catch (...)
	{
		WriteLog("ViolenceSearch error\r\n", strlen("ViolenceSearch error\r\n"), WRITE_LOG_ERROR);
		return FALSE;
	}
}


int __stdcall WriteLog(char* Pack, int PackLen, DWORD dwFlag)
{
	HANDLE hf = INVALID_HANDLE_VALUE;
	if (dwFlag == WRITE_LOG_ERROR_PACKET)
	{
		hf = CreateFileA(ERROR_PACKET_FILE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	}
	else if (dwFlag == WRITE_LOG_ERROR)
	{
		hf = CreateFileA(HOOK_QQ_LOG_FILE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	}
	else if (dwFlag == WRITE_LOG_MSG)
	{
		hf = CreateFileA(QQ_MSG_FILE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	}
	else
	{
		return FALSE;
	}

	if (hf == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD fsize = SetFilePointer(hf, 0, 0, FILE_END);
	if (fsize == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hf);
		return FALSE;
	}

	DWORD dwCnt = 0;
	int iRet = 0;
	if (dwFlag == WRITE_LOG_ERROR_PACKET)
	{
		iRet = WriteFile(hf, "something has wrong in this packet:", strlen("something has wrong in this packet:"), &dwCnt, 0);
	}

	iRet = WriteFile(hf, Pack, PackLen, &dwCnt, 0);
	CloseHandle(hf);
	if (iRet == 0 || dwCnt != PackLen)
	{
		return FALSE;
	}
	return TRUE;
}


unsigned int  __stdcall GetApiAddrFromDll(unsigned int  pIdh, char* lpApiName, int iApiNameLen)
{
	IMAGE_NT_HEADERS* pInth = (IMAGE_NT_HEADERS*)(*(unsigned int*)(pIdh + 0x3c) + pIdh);
	IMAGE_EXPORT_DIRECTORY* pIed = (IMAGE_EXPORT_DIRECTORY*)(pIdh + pInth->OptionalHeader.DataDirectory->VirtualAddress);
	unsigned int pVaAddrOfNames = pIed->AddressOfNames + pIdh;
	unsigned int iNumsOfNames = pIed->NumberOfNames;

	while (iNumsOfNames)
	{
		int pNames = *(unsigned int*)pVaAddrOfNames + pIdh;
		int iLen = 0;
		for (iLen = 0; iLen < iApiNameLen; iLen++)
		{
			if (lpApiName[iLen] != *(char*)(pNames + iLen))
			{
				break;
			}
		}

		if (iLen != iApiNameLen)
		{
			pVaAddrOfNames += 4;
			iNumsOfNames--;
			continue;
		}

		pVaAddrOfNames = pVaAddrOfNames - pIed->AddressOfNames;
		pVaAddrOfNames = pVaAddrOfNames - pIdh;
		pVaAddrOfNames = pVaAddrOfNames >> 1;
		pVaAddrOfNames = pVaAddrOfNames + pIed->AddressOfNameOrdinals;
		pVaAddrOfNames = pVaAddrOfNames + pIdh;
		unsigned int sOrdinals = *(unsigned short*)pVaAddrOfNames;
		sOrdinals = sOrdinals << 2;
		sOrdinals = sOrdinals + pIed->AddressOfFunctions;
		sOrdinals = sOrdinals + pIdh;
		unsigned int pVaAddr = *(unsigned int*)sOrdinals + pIdh;
		return pVaAddr;
	}

	return FALSE;
}