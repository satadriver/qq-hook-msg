#include <tchar.h>
#include <Windows.h>
#include <Psapi.h>


#pragma comment(lib, "Psapi.lib") 

#define TARGET_PROGRAM_NAME		"QQ.EXE"
#define TARGET_DLL_NAME			"HookQQMsgDll.dll"
#define MUTEX_NAME				"HOOK_QQ_MSG_MUTEX"
#define SEMPHORE_NAME			"HOOK_QQ_MSG_SEMPHORE"

DWORD FindProc(LPCSTR lpName)
{
	DWORD aProcId[4096] = { 0 };
	DWORD dwProcCnt = 0;
	DWORD dwModCnt = 0;
	char szPath[MAX_PATH] = { 0 };
	HMODULE hMod = 0;

	if (!EnumProcesses(aProcId, sizeof(aProcId), &dwProcCnt))
	{
		return FALSE;
	}

	for (DWORD i = 0; i < dwProcCnt; ++i)
	{
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcId[i]);
		if (NULL != hProc)
		{
			if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &dwModCnt))
			{
				GetModuleBaseNameA(hProc, hMod, szPath, MAX_PATH);
				if (0 == _stricmp(szPath, lpName))
				{
					CloseHandle(hProc);
					return aProcId[i];
				}
			}
			CloseHandle(hProc);
		}
	}
	return FALSE;
}



int __stdcall WinMain(__in HINSTANCE hInstance, __in_opt HINSTANCE hPrevInstance, __in LPSTR lpCmdLine, __in int nShowCmd)
{

	HANDLE hMutex = CreateMutexA(0, TRUE, MUTEX_NAME);
	int iRet = GetLastError();
	if (hMutex && iRet == ERROR_ALREADY_EXISTS)
	{
		MessageBoxA(0, "程序已经在运行,请关闭当前程序", "程序已经在运行,请关闭当前程序", MB_OK);
		ExitProcess(0);
	}

	DWORD dwProcID = 0;
	dwProcID = FindProc(TARGET_PROGRAM_NAME);
	if (dwProcID == 0)
	{
		MessageBoxA(0, "未发现QQ进程,请打开QQ并等待", "未发现QQ进程,请打开QQ并等待", MB_OK);
		return FALSE;
	}

	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcID);
	if (NULL == hTarget)
	{
		MessageBoxA(0, "open process error", "open process error", MB_OK);
		return FALSE;
	}

	HMODULE hKernel32 = GetModuleHandle(_T("Kernel32"));
	LPTHREAD_START_ROUTINE pLoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	LPTHREAD_START_ROUTINE pFreeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "FreeLibrary");
	if (NULL == pLoadLib || NULL == pFreeLib)
	{
		MessageBoxA(0, "GetProcAddress error", "GetProcAddress error", MB_OK);
		CloseHandle(hTarget);
		return FALSE;
	}



	HANDLE hf = CreateFileA(TARGET_DLL_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		iRet = GetLastError();
		MessageBoxA(0, "not found dll file", "not found dll file", MB_OK);
		CloseHandle(hTarget);
		return FALSE;
	}
	CloseHandle(hf);

	char strDllFullPath[MAX_PATH] = { 0 };
	int iDllFullPathLen = 0;
	iDllFullPathLen = GetCurrentDirectoryA(MAX_PATH, strDllFullPath);
	*(strDllFullPath + iDllFullPathLen) = '\\';
	*(strDllFullPath + iDllFullPathLen + 1) = 0;
	iRet = SetCurrentDirectoryA(strDllFullPath);
	lstrcatA(strDllFullPath, TARGET_DLL_NAME);

	WCHAR szPath[MAX_PATH] = { 0 };
	iRet = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, strDllFullPath, -1, szPath, sizeof(szPath) / sizeof(szPath[0]));
	LPVOID lpMem = VirtualAllocEx(hTarget, NULL, sizeof(szPath), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == lpMem)
	{
		MessageBoxA(0, "VirtualAllocEx error", "VirtualAllocEx error", MB_OK);
		CloseHandle(hTarget);
		return FALSE;
	}

	iRet = WriteProcessMemory(hTarget, lpMem, (void*)szPath, sizeof(szPath), NULL);
	if (iRet == 0)
	{
		MessageBoxA(0, "WriteProcessMemory error,please wait few seconds", "WriteProcessMemory error,please wait few seconds", MB_OK);
	}


	HANDLE hThread = CreateRemoteThread(hTarget, NULL, 0, pLoadLib, lpMem, 0, NULL);
	if (NULL == hThread)
	{
		CloseHandle(hTarget);
		MessageBoxA(0, "CreateRemoteThread error", "CreateRemoteThread error", MB_OK);
		return FALSE;
	}

	DWORD dwretcode;
	iRet = WaitForSingleObject(hThread, INFINITE);
	if (iRet == WAIT_OBJECT_0)
	{
		iRet = GetExitCodeThread(hThread, &dwretcode);
	}
	CloseHandle(hThread);


	hThread = CreateRemoteThread(hTarget, NULL, 0, pFreeLib, (void*)lpMem, 0, NULL);
	if (NULL == hThread)
	{
		CloseHandle(hTarget);
		return FALSE;
	}

	iRet = WaitForSingleObject(hThread, INFINITE);

	if (iRet == WAIT_OBJECT_0)
	{
		iRet = GetExitCodeThread(hThread, &dwretcode);

		iRet = VirtualFreeEx(hTarget, lpMem, 0, MEM_DECOMMIT | MEM_RELEASE);
	}

	CloseHandle(hThread);

	CloseHandle(hTarget);

	return TRUE;
}