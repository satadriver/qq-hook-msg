#include <tchar.h>
#include <Windows.h>




#define MAX_MESSAGE_LENGTH							0x1000

#define QQ_NAME_MAX_SIZE							256


#define HOST_IP_ADDR "192.168.157.40"

#define HOOKED_DLL_NAME								"Common.dll"
#define HOOKED_FUNCTION_NAME_oi_symmetry_decrypt2	"?oi_symmetry_decrypt2"
#define HOOKED_FUNCTION_NAME_oi_symmetry_encrypt2	"?oi_symmetry_encrypt2"
#define SEMPHORE_NAME								"HOOK_QQ_MSG_SEMPHORE"

typedef void(__cdecl* QQ_oi_symmetry_decrypt2)(char* strSrc, unsigned int iSrcLen, char* strKey, char* strDst, int* iDstLen);
typedef void(__cdecl* QQ_oi_symmetry_encrypt2)(char* strSrc, unsigned int iSrcLen, char* strKey, char* strDst, int* iDstLen);



extern char SAVE_SEND_PACK_FILE_NAME[MAX_PATH];
extern char SAVE_RECEIVE_PACK_FILE_NAME[MAX_PATH];
extern char QQ_MSG_FILE_NAME[MAX_PATH];
extern char HOOK_QQ_LOG_FILE_NAME[MAX_PATH];
extern char ERROR_PACKET_FILE_NAME[MAX_PATH];



int				__stdcall	ParseQQDataPack(char* Pack, int PackLen);

int				__stdcall	InitVariables();

BOOL			__stdcall	MonitorBase_oi_symmetry_decrypt2();
BOOL			__stdcall	ReleaseBase_oi_symmetry_decrypt2();
BOOL			__stdcall	UninstallMonitor_oi_symmetry_decrypt2();
void			__cdecl		MonFunc_oi_symmetry_decrypt2(char* strSrc, unsigned int iSrcLen, char* strKey, char* strDst, int* iDstLen);
BOOL			__stdcall	InstallMonitor_oi_symmetry_decrypt2();
BOOL			__stdcall	MonitorBase_oi_symmetry_encrypt2();
BOOL			__stdcall	ReleaseBase_oi_symmetry_encrypt2();
BOOL			__stdcall	UninstallMonitor_oi_symmetry_encrypt2();
void			__cdecl		MonFunc_oi_symmetry_encrypt2(char* strSrc, unsigned int iSrcLen, char* strKey, char* strDst, int* iDstLen);
BOOL			__stdcall	InstallMonitor_oi_symmetry_encrypt2();
BOOL			__stdcall	DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved);
