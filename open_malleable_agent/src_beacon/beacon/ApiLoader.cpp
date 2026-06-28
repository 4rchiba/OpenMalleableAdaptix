#include "ApiLoader.h"
#include "ProcLoader.h"

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* Destination, int Value, size_t Size)
{
	unsigned char* p = (unsigned char*)Destination;
	unsigned char val = (unsigned char)Value;
	
	// Word-aligned fill for larger blocks
	if (Size >= sizeof(size_t)) {
		size_t pattern = val;
		for (size_t i = 1; i < sizeof(size_t); i++)
			pattern |= (pattern << 8);
		
		while (((size_t)p & (sizeof(size_t) - 1)) && Size) {
			*p++ = val;
			Size--;
		}
		while (Size >= sizeof(size_t)) {
			*(size_t*)p = pattern;
			p += sizeof(size_t);
			Size -= sizeof(size_t);
		}
	}
	while (Size--)
		*p++ = val;
	
	return Destination;
}

#pragma intrinsic(memcpy)
#pragma function(memcpy)
void* __cdecl memcpy(void* Dst, const void* Src, size_t Size)
{
	unsigned char* d = (unsigned char*)Dst;
	const unsigned char* s = (const unsigned char*)Src;
	
	// Word-aligned copy for larger blocks
	if (Size >= sizeof(size_t) && (((size_t)d | (size_t)s) & (sizeof(size_t) - 1)) == 0) {
		while (Size >= sizeof(size_t)) {
			*(size_t*)d = *(const size_t*)s;
			d += sizeof(size_t);
			s += sizeof(size_t);
			Size -= sizeof(size_t);
		}
	}
	while (Size--)
		*d++ = *s++;
	
	return Dst;
}

CHAR HdChrA(CHAR c) { return c; }
WCHAR HdChrW(WCHAR c) { return c; }

SYSMODULES* SysModules = NULL;
WINAPIFUNC* ApiWin     = NULL;
NTAPIFUNC*  ApiNt      = NULL;

#if defined(API_RESOLUTION_GETPROCADDRESS)
#define GPA(module, name) (decltype(name)*)getProc((module), #name)
#define GPA_TYPED(type, module, name) (type)getProc((module), (name))

BOOL ApiLoad()
{
	static SYSMODULES sysModulesStorage;
	static WINAPIFUNC apiWinStorage;
	static NTAPIFUNC apiNtStorage;

	memset(&sysModulesStorage, 0, sizeof(sysModulesStorage));
	memset(&apiWinStorage, 0, sizeof(apiWinStorage));
	memset(&apiNtStorage, 0, sizeof(apiNtStorage));

	SysModules = &sysModulesStorage;
	ApiWin = &apiWinStorage;
	ApiNt = &apiNtStorage;

	HMODULE(WINAPI * loadLibrary)(LPCSTR) = LoadLibraryA;
	FARPROC(WINAPI * getProc)(HMODULE, LPCSTR) = GetProcAddress;

	HMODULE hKernel32Module = loadLibrary("kernel32.dll");
	HMODULE hNtdllModule = loadLibrary("ntdll.dll");
	HMODULE hIphlpapiModule = loadLibrary("iphlpapi.dll");
	HMODULE hAdvapi32Module = loadLibrary("advapi32.dll");
	HMODULE hMsvcrtModule = loadLibrary("msvcrt.dll");
	HMODULE hWs2_32Module = loadLibrary("ws2_32.dll");
	HMODULE hPsapiModule = loadLibrary("psapi.dll");

	SysModules->Kernel32 = hKernel32Module;
	SysModules->Ntdll = hNtdllModule;
	SysModules->Iphlpapi = hIphlpapiModule;
	SysModules->Advapi32 = hAdvapi32Module;
	SysModules->Msvcrt = hMsvcrtModule;
	SysModules->Ws2_32 = hWs2_32Module;

	if (!hKernel32Module || !hNtdllModule)
		return FALSE;

	ApiWin->LoadLibraryA = loadLibrary;
	ApiWin->GetProcAddress = getProc;

	ApiWin->CopyFileA = GPA(hKernel32Module, CopyFileA);
	ApiWin->CreateDirectoryA = GPA(hKernel32Module, CreateDirectoryA);
	ApiWin->CreateFileA = GPA(hKernel32Module, CreateFileA);
	ApiWin->CreateNamedPipeA = GPA(hKernel32Module, CreateNamedPipeA);
	ApiWin->CreatePipe = GPA(hKernel32Module, CreatePipe);
	ApiWin->CreateProcessA = GPA(hKernel32Module, CreateProcessA);
	ApiWin->CreateEventA = GPA(hKernel32Module, CreateEventA);
	ApiWin->CreateThread = GPA(hKernel32Module, CreateThread);
	ApiWin->CreateThreadpoolTimer = GPA(hKernel32Module, CreateThreadpoolTimer);
	ApiWin->DisconnectNamedPipe = GPA(hKernel32Module, DisconnectNamedPipe);
	ApiWin->DeleteCriticalSection = GPA(hKernel32Module, DeleteCriticalSection);
	ApiWin->DeleteFileA = GPA(hKernel32Module, DeleteFileA);
	ApiWin->EnterCriticalSection = GPA(hKernel32Module, EnterCriticalSection);
	ApiWin->TryEnterCriticalSection = GPA(hKernel32Module, TryEnterCriticalSection);
	ApiWin->FindClose = GPA(hKernel32Module, FindClose);
	ApiWin->FindFirstFileA = GPA(hKernel32Module, FindFirstFileA);
	ApiWin->FindNextFileA = GPA(hKernel32Module, FindNextFileA);
	ApiWin->FreeLibrary = GPA(hKernel32Module, FreeLibrary);
	ApiWin->GetACP = GPA(hKernel32Module, GetACP);
	ApiWin->GetComputerNameExA = GPA(hKernel32Module, GetComputerNameExA);
	ApiWin->GetCurrentDirectoryA = GPA(hKernel32Module, GetCurrentDirectoryA);
	ApiWin->GetDriveTypeA = GPA(hKernel32Module, GetDriveTypeA);
	ApiWin->GetExitCodeProcess = GPA(hKernel32Module, GetExitCodeProcess);
	ApiWin->GetExitCodeThread = GPA(hKernel32Module, GetExitCodeThread);
	ApiWin->GetFileSize = GPA(hKernel32Module, GetFileSize);
	ApiWin->GetFileAttributesA = GPA(hKernel32Module, GetFileAttributesA);
	ApiWin->GetFullPathNameA = GPA(hKernel32Module, GetFullPathNameA);
	ApiWin->GetLastError = GPA(hKernel32Module, GetLastError);
	ApiWin->GetLogicalDrives = GPA(hKernel32Module, GetLogicalDrives);
	ApiWin->GetOEMCP = GPA(hKernel32Module, GetOEMCP);
	ApiWin->GetModuleBaseNameA = hPsapiModule ? GPA(hPsapiModule, GetModuleBaseNameA) : (decltype(GetModuleBaseNameA)*)getProc(hKernel32Module, "K32GetModuleBaseNameA");
	ApiWin->GetModuleHandleA = GPA(hKernel32Module, GetModuleHandleA);
	ApiWin->GetLocalTime = GPA(hKernel32Module, GetLocalTime);
	ApiWin->GetSystemTimeAsFileTime = GPA(hKernel32Module, GetSystemTimeAsFileTime);
	ApiWin->GetTickCount = GPA(hKernel32Module, GetTickCount);
	ApiWin->GetTimeZoneInformation = GPA(hKernel32Module, GetTimeZoneInformation);
	ApiWin->HeapAlloc = GPA(hKernel32Module, HeapAlloc);
	ApiWin->HeapCreate = GPA(hKernel32Module, HeapCreate);
	ApiWin->HeapDestroy = GPA(hKernel32Module, HeapDestroy);
	ApiWin->HeapReAlloc = GPA(hKernel32Module, HeapReAlloc);
	ApiWin->HeapFree = GPA(hKernel32Module, HeapFree);
	ApiWin->InitializeCriticalSection = GPA(hKernel32Module, InitializeCriticalSection);
	ApiWin->IsWow64Process = GPA(hKernel32Module, IsWow64Process);
	ApiWin->LocalAlloc = GPA(hKernel32Module, LocalAlloc);
	ApiWin->LocalFree = GPA(hKernel32Module, LocalFree);
	ApiWin->LocalReAlloc = GPA(hKernel32Module, LocalReAlloc);
	ApiWin->LeaveCriticalSection = GPA(hKernel32Module, LeaveCriticalSection);
	ApiWin->MoveFileA = GPA(hKernel32Module, MoveFileA);
	ApiWin->MultiByteToWideChar = GPA(hKernel32Module, MultiByteToWideChar);
	ApiWin->PeekNamedPipe = GPA(hKernel32Module, PeekNamedPipe);
	ApiWin->ReadFile = GPA(hKernel32Module, ReadFile);
	ApiWin->RemoveDirectoryA = GPA(hKernel32Module, RemoveDirectoryA);
	ApiWin->RtlCaptureContext = GPA(hKernel32Module, RtlCaptureContext);
	ApiWin->SetCurrentDirectoryA = GPA(hKernel32Module, SetCurrentDirectoryA);
	ApiWin->SetNamedPipeHandleState = GPA(hKernel32Module, SetNamedPipeHandleState);
	ApiWin->SetEvent = GPA(hKernel32Module, SetEvent);
	ApiWin->ResetEvent = GPA(hKernel32Module, ResetEvent);
	ApiWin->SetThreadpoolTimer = GPA(hKernel32Module, SetThreadpoolTimer);
	ApiWin->Sleep = GPA(hKernel32Module, Sleep);
	ApiWin->VirtualAlloc = GPA(hKernel32Module, VirtualAlloc);
	ApiWin->VirtualFree = GPA(hKernel32Module, VirtualFree);
	ApiWin->WaitForSingleObject = GPA(hKernel32Module, WaitForSingleObject);
	ApiWin->WaitNamedPipeA = GPA(hKernel32Module, WaitNamedPipeA);
	ApiWin->WideCharToMultiByte = GPA(hKernel32Module, WideCharToMultiByte);
	ApiWin->WriteFile = GPA(hKernel32Module, WriteFile);
	ApiWin->CloseThreadpoolTimer = GPA(hKernel32Module, CloseThreadpoolTimer);

	if (hIphlpapiModule)
		ApiWin->GetAdaptersInfo = GPA(hIphlpapiModule, GetAdaptersInfo);

	if (hAdvapi32Module) {
		ApiWin->GetTokenInformation = GPA(hAdvapi32Module, GetTokenInformation);
		ApiWin->RegisterServiceCtrlHandlerA = GPA(hAdvapi32Module, RegisterServiceCtrlHandlerA);
		ApiWin->SetServiceStatus = GPA(hAdvapi32Module, SetServiceStatus);
		ApiWin->StartServiceCtrlDispatcherA = GPA(hAdvapi32Module, StartServiceCtrlDispatcherA);
		ApiWin->GetUserNameA = GPA(hAdvapi32Module, GetUserNameA);
		ApiWin->LookupAccountSidA = GPA(hAdvapi32Module, LookupAccountSidA);
		ApiWin->RevertToSelf = GPA(hAdvapi32Module, RevertToSelf);
		ApiWin->ImpersonateLoggedOnUser = GPA(hAdvapi32Module, ImpersonateLoggedOnUser);
		ApiWin->SetThreadToken = GPA(hAdvapi32Module, SetThreadToken);
		ApiWin->DuplicateTokenEx = GPA(hAdvapi32Module, DuplicateTokenEx);
		ApiWin->CreateProcessAsUserA = GPA(hAdvapi32Module, CreateProcessAsUserA);
		ApiWin->CreateProcessWithTokenW = GPA(hAdvapi32Module, CreateProcessWithTokenW);
	}

	if (hMsvcrtModule) {
#if defined(DEBUG)
		ApiWin->printf = GPA_TYPED(printf_t, hMsvcrtModule, "printf");
#endif
		ApiWin->vsnprintf = GPA_TYPED(vsnprintf_t, hMsvcrtModule, "vsnprintf");
		if (!ApiWin->vsnprintf)
			ApiWin->vsnprintf = GPA_TYPED(vsnprintf_t, hMsvcrtModule, "_vsnprintf");
		ApiWin->snprintf = GPA_TYPED(snprintf_t, hMsvcrtModule, "snprintf");
		if (!ApiWin->snprintf)
			ApiWin->snprintf = GPA_TYPED(snprintf_t, hMsvcrtModule, "_snprintf");
	}

	if (hWs2_32Module) {
		ApiWin->WSAStartup = GPA(hWs2_32Module, WSAStartup);
		ApiWin->WSACleanup = GPA(hWs2_32Module, WSACleanup);
		ApiWin->socket = GPA(hWs2_32Module, socket);
		ApiWin->gethostbyname = GPA(hWs2_32Module, gethostbyname);
		ApiWin->ioctlsocket = GPA(hWs2_32Module, ioctlsocket);
		ApiWin->connect = GPA(hWs2_32Module, connect);
		ApiWin->setsockopt = GPA(hWs2_32Module, setsockopt);
		ApiWin->getsockopt = GPA(hWs2_32Module, getsockopt);
		ApiWin->WSAGetLastError = GPA(hWs2_32Module, WSAGetLastError);
		ApiWin->closesocket = GPA(hWs2_32Module, closesocket);
		ApiWin->select = GPA(hWs2_32Module, select);
		ApiWin->__WSAFDIsSet = GPA(hWs2_32Module, __WSAFDIsSet);
		ApiWin->shutdown = GPA(hWs2_32Module, shutdown);
		ApiWin->recv = GPA(hWs2_32Module, recv);
		ApiWin->recvfrom = GPA(hWs2_32Module, recvfrom);
		ApiWin->send = GPA(hWs2_32Module, send);
		ApiWin->sendto = GPA(hWs2_32Module, sendto);
		ApiWin->accept = GPA(hWs2_32Module, accept);
		ApiWin->listen = GPA(hWs2_32Module, listen);
		ApiWin->bind = GPA(hWs2_32Module, bind);
	}

	ApiNt->NtClose = GPA(hNtdllModule, NtClose);
	ApiNt->NtContinue = GPA(hNtdllModule, NtContinue);
	ApiNt->NtFreeVirtualMemory = GPA(hNtdllModule, NtFreeVirtualMemory);
	ApiNt->NtQueryInformationProcess = GPA(hNtdllModule, NtQueryInformationProcess);
	ApiNt->NtQuerySystemInformation = GPA(hNtdllModule, NtQuerySystemInformation);
	ApiNt->NtOpenProcess = GPA(hNtdllModule, NtOpenProcess);
	ApiNt->NtOpenProcessToken = GPA(hNtdllModule, NtOpenProcessToken);
	ApiNt->NtOpenThreadToken = GPA(hNtdllModule, NtOpenThreadToken);
	ApiNt->NtTerminateThread = GPA(hNtdllModule, NtTerminateThread);
	ApiNt->NtTerminateProcess = GPA(hNtdllModule, NtTerminateProcess);
	ApiNt->RtlGetVersion = GPA(hNtdllModule, RtlGetVersion);
	ApiNt->RtlExitUserThread = GPA(hNtdllModule, RtlExitUserThread);
	ApiNt->RtlExitUserProcess = GPA(hNtdllModule, RtlExitUserProcess);
	ApiNt->RtlIpv4StringToAddressA = GPA(hNtdllModule, RtlIpv4StringToAddressA);
	ApiNt->RtlRandomEx = GPA(hNtdllModule, RtlRandomEx);
	ApiNt->RtlNtStatusToDosError = GPA(hNtdllModule, RtlNtStatusToDosError);

	return TRUE;
}

#undef GPA_TYPED
#undef GPA
#elif !defined(IAT_HIDING)
BOOL ApiLoad()
{
	SysModules = (SYSMODULES*)LocalAlloc(LPTR, sizeof(SYSMODULES));
	ApiWin     = (WINAPIFUNC*)LocalAlloc(LPTR, sizeof(WINAPIFUNC));
	ApiNt      = (NTAPIFUNC*)LocalAlloc(LPTR, sizeof(NTAPIFUNC));
	if (!SysModules || !ApiWin || !ApiNt)
		return FALSE;

	SysModules->Kernel32 = GetModuleHandleA("kernel32.dll");
	SysModules->Ntdll    = GetModuleHandleA("ntdll.dll");
	SysModules->Iphlpapi = LoadLibraryA("iphlpapi.dll");
	SysModules->Advapi32 = LoadLibraryA("advapi32.dll");
	SysModules->Msvcrt   = LoadLibraryA("msvcrt.dll");
	SysModules->Ws2_32   = LoadLibraryA("ws2_32.dll");

	ApiWin->CopyFileA                = CopyFileA;
	ApiWin->CreateDirectoryA         = CreateDirectoryA;
	ApiWin->CreateFileA              = CreateFileA;
	ApiWin->CreateNamedPipeA         = CreateNamedPipeA;
	ApiWin->CreatePipe               = CreatePipe;
	ApiWin->CreateProcessA           = CreateProcessA;
	ApiWin->CreateEventA             = CreateEventA;
	ApiWin->CreateThread             = CreateThread;
	ApiWin->CreateThreadpoolTimer    = CreateThreadpoolTimer;
	ApiWin->DisconnectNamedPipe      = DisconnectNamedPipe;
	ApiWin->DeleteCriticalSection    = DeleteCriticalSection;
	ApiWin->DeleteFileA              = DeleteFileA;
	ApiWin->EnterCriticalSection     = EnterCriticalSection;
	ApiWin->TryEnterCriticalSection  = TryEnterCriticalSection;
	ApiWin->FindClose                = FindClose;
	ApiWin->FindFirstFileA           = FindFirstFileA;
	ApiWin->FindNextFileA            = FindNextFileA;
	ApiWin->FreeLibrary              = FreeLibrary;
	ApiWin->GetACP                   = GetACP;
	ApiWin->GetComputerNameExA       = GetComputerNameExA;
	ApiWin->GetCurrentDirectoryA     = GetCurrentDirectoryA;
	ApiWin->GetDriveTypeA            = GetDriveTypeA;
	ApiWin->GetExitCodeProcess       = GetExitCodeProcess;
	ApiWin->GetExitCodeThread        = GetExitCodeThread;
	ApiWin->GetFileSize              = GetFileSize;
	ApiWin->GetFileAttributesA       = GetFileAttributesA;
	ApiWin->GetFullPathNameA         = GetFullPathNameA;
	ApiWin->GetLastError             = GetLastError;
	ApiWin->GetLogicalDrives         = GetLogicalDrives;
	ApiWin->GetOEMCP                 = GetOEMCP;
	ApiWin->GetModuleBaseNameA       = GetModuleBaseNameA;
	ApiWin->GetModuleHandleA         = GetModuleHandleA;
	ApiWin->GetProcAddress           = GetProcAddress;
	ApiWin->GetLocalTime             = GetLocalTime;
	ApiWin->GetSystemTimeAsFileTime  = GetSystemTimeAsFileTime;
	ApiWin->GetTickCount             = GetTickCount;
	ApiWin->GetTimeZoneInformation   = GetTimeZoneInformation;
	ApiWin->HeapAlloc                = HeapAlloc;
	ApiWin->HeapCreate               = HeapCreate;
	ApiWin->HeapDestroy              = HeapDestroy;
	ApiWin->HeapReAlloc              = HeapReAlloc;
	ApiWin->HeapFree                 = HeapFree;
	ApiWin->InitializeCriticalSection = InitializeCriticalSection;
	ApiWin->IsWow64Process           = IsWow64Process;
	ApiWin->LoadLibraryA             = LoadLibraryA;
	ApiWin->LocalAlloc               = LocalAlloc;
	ApiWin->LocalFree                = LocalFree;
	ApiWin->LocalReAlloc             = LocalReAlloc;
	ApiWin->LeaveCriticalSection     = LeaveCriticalSection;
	ApiWin->MoveFileA                = MoveFileA;
	ApiWin->MultiByteToWideChar      = MultiByteToWideChar;
	ApiWin->PeekNamedPipe            = PeekNamedPipe;
	ApiWin->ReadFile                 = ReadFile;
	ApiWin->RemoveDirectoryA         = RemoveDirectoryA;
	ApiWin->RtlCaptureContext        = RtlCaptureContext;
	ApiWin->SetCurrentDirectoryA     = SetCurrentDirectoryA;
	ApiWin->SetNamedPipeHandleState  = SetNamedPipeHandleState;
	ApiWin->SetEvent                 = SetEvent;
	ApiWin->ResetEvent               = ResetEvent;
	ApiWin->SetThreadpoolTimer       = SetThreadpoolTimer;
	ApiWin->Sleep                    = Sleep;
	ApiWin->VirtualAlloc             = VirtualAlloc;
	ApiWin->VirtualFree              = VirtualFree;
	ApiWin->WaitForSingleObject      = WaitForSingleObject;
	ApiWin->WaitNamedPipeA           = WaitNamedPipeA;
	ApiWin->WideCharToMultiByte      = WideCharToMultiByte;
	ApiWin->WriteFile                = WriteFile;
	ApiWin->CloseThreadpoolTimer     = CloseThreadpoolTimer;

	ApiWin->GetAdaptersInfo          = GetAdaptersInfo;

	ApiWin->GetTokenInformation      = GetTokenInformation;
	ApiWin->RegisterServiceCtrlHandlerA = RegisterServiceCtrlHandlerA;
	ApiWin->SetServiceStatus         = SetServiceStatus;
	ApiWin->StartServiceCtrlDispatcherA = StartServiceCtrlDispatcherA;
	ApiWin->GetUserNameA             = GetUserNameA;
	ApiWin->LookupAccountSidA        = LookupAccountSidA;
	ApiWin->RevertToSelf             = RevertToSelf;
	ApiWin->ImpersonateLoggedOnUser  = ImpersonateLoggedOnUser;
	ApiWin->SetThreadToken           = SetThreadToken;
	ApiWin->DuplicateTokenEx         = DuplicateTokenEx;
	ApiWin->CreateProcessAsUserA     = CreateProcessAsUserA;
	ApiWin->CreateProcessWithTokenW  = CreateProcessWithTokenW;

#if defined(DEBUG)
	ApiWin->printf = printf;
#endif
	ApiWin->vsnprintf = _vsnprintf;
	ApiWin->snprintf  = _snprintf;

	ApiWin->WSAStartup      = WSAStartup;
	ApiWin->WSACleanup      = WSACleanup;
	ApiWin->socket          = socket;
	ApiWin->gethostbyname   = gethostbyname;
	ApiWin->ioctlsocket     = ioctlsocket;
	ApiWin->connect         = connect;
	ApiWin->setsockopt      = setsockopt;
	ApiWin->getsockopt      = getsockopt;
	ApiWin->WSAGetLastError = WSAGetLastError;
	ApiWin->closesocket     = closesocket;
	ApiWin->select          = select;
	ApiWin->__WSAFDIsSet    = __WSAFDIsSet;
	ApiWin->shutdown        = shutdown;
	ApiWin->recv            = recv;
	ApiWin->recvfrom        = recvfrom;
	ApiWin->send            = send;
	ApiWin->sendto          = sendto;
	ApiWin->accept          = accept;
	ApiWin->listen          = listen;
	ApiWin->bind            = bind;

	ApiNt->NtClose                   = NtClose;
	ApiNt->NtContinue                = NtContinue;
	ApiNt->NtFreeVirtualMemory       = NtFreeVirtualMemory;
	ApiNt->NtQueryInformationProcess = NtQueryInformationProcess;
	ApiNt->NtQuerySystemInformation  = NtQuerySystemInformation;
	ApiNt->NtOpenProcess             = NtOpenProcess;
	ApiNt->NtOpenProcessToken        = NtOpenProcessToken;
	ApiNt->NtOpenThreadToken         = NtOpenThreadToken;
	ApiNt->NtTerminateThread         = NtTerminateThread;
	ApiNt->NtTerminateProcess        = NtTerminateProcess;
	ApiNt->RtlGetVersion             = RtlGetVersion;
	ApiNt->RtlExitUserThread         = RtlExitUserThread;
	ApiNt->RtlExitUserProcess        = RtlExitUserProcess;
	ApiNt->RtlIpv4StringToAddressA   = RtlIpv4StringToAddressA;
	ApiNt->RtlRandomEx               = RtlRandomEx;
	ApiNt->RtlNtStatusToDosError     = RtlNtStatusToDosError;

	return TRUE;
}
#else
BOOL ApiLoad()
{
	HMODULE hKernel32Module = GetModuleAddress(HASH_LIB_KERNEL32);

	decltype(LocalAlloc)* allocProc = (decltype(LocalAlloc)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_LOCALALLOC);

	SysModules = (SYSMODULES*) allocProc(LPTR, sizeof(SYSMODULES));
	ApiWin     = (WINAPIFUNC*) allocProc(LPTR, sizeof(WINAPIFUNC));
	ApiNt      = (NTAPIFUNC*)  allocProc(LPTR, sizeof(NTAPIFUNC));

	SysModules->Kernel32 = hKernel32Module;

	if ( ApiWin && hKernel32Module) {
		// kernel32
		ApiWin->LoadLibraryA = (decltype(LoadLibraryA)*)GetSymbolAddress(hKernel32Module, HASH_FUNC_LOADLIBRARYA);

		ApiWin->CopyFileA				= (decltype(CopyFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_COPYFILEA);
		ApiWin->CreateDirectoryA		= (decltype(CreateDirectoryA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEDIRECTORYA);
		ApiWin->CreateFileA				= (decltype(CreateFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEFILEA);
		ApiWin->CreateNamedPipeA        = (decltype(CreateNamedPipeA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATENAMEDPIPEA);
		ApiWin->CreatePipe				= (decltype(CreatePipe)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEPIPE);
		ApiWin->CreateProcessA			= (decltype(CreateProcessA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEPROCESSA);
		ApiWin->CreateEventA            = (decltype(CreateEventA)*)            GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEEVENTA);
		ApiWin->CreateThread            = (decltype(CreateThread)*)            GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATETHREAD);
		ApiWin->CreateThreadpoolTimer   = (decltype(CreateThreadpoolTimer)*)   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATETHREADPOOLTIMER);
		ApiWin->DisconnectNamedPipe     = (decltype(DisconnectNamedPipe)*)     GetSymbolAddress(hKernel32Module, HASH_FUNC_DISCONNECTNAMEDPIPE);
		ApiWin->DeleteCriticalSection   = (decltype(DeleteCriticalSection)*)   GetSymbolAddress(hKernel32Module, HASH_FUNC_DELETECRITICALSECTION);
		ApiWin->DeleteFileA				= (decltype(DeleteFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_DELETEFILEA);
		ApiWin->EnterCriticalSection    = (decltype(EnterCriticalSection)*)    GetSymbolAddress(hKernel32Module, HASH_FUNC_ENTERCRITICALSECTION);
		ApiWin->TryEnterCriticalSection = (decltype(TryEnterCriticalSection)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_TRYENTERCRITICALSECTION);
		ApiWin->GetExitCodeProcess		= (decltype(GetExitCodeProcess)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETEXITCODEPROCESS);
		ApiWin->GetExitCodeThread		= (decltype(GetExitCodeThread)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETEXITCODETHREAD);
		ApiWin->FindClose				= (decltype(FindClose)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_FINDCLOSE);
		ApiWin->FindFirstFileA			= (decltype(FindFirstFileA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_FINDFIRSTFILEA);
		ApiWin->FindNextFileA			= (decltype(FindNextFileA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_FINDNEXTFILEA);
		ApiWin->FreeLibrary				= (decltype(FreeLibrary)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_FREELIBRARY);
		ApiWin->GetACP					= (decltype(GetACP)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETACP);
		ApiWin->GetComputerNameExA		= (decltype(GetComputerNameExA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETCOMPUTERNAMEEXA);
		ApiWin->GetCurrentDirectoryA	= (decltype(GetCurrentDirectoryA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETCURRENTDIRECTORYA);
		ApiWin->GetDriveTypeA			= (decltype(GetDriveTypeA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETDRIVETYPEA);
		ApiWin->GetFileSize				= (decltype(GetFileSize)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETFILESIZE);
		ApiWin->GetFileAttributesA		= (decltype(GetFileAttributesA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETFILEATTRIBUTESA);
		ApiWin->GetFullPathNameA		= (decltype(GetFullPathNameA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETFULLPATHNAMEA);
		ApiWin->GetLastError			= (decltype(GetLastError)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETLASTERROR);
		ApiWin->GetLogicalDrives		= (decltype(GetLogicalDrives)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETLOGICALDRIVES);
		ApiWin->GetOEMCP				= (decltype(GetOEMCP)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETOEMCP);
		ApiWin->GetModuleBaseNameA		= (decltype(GetModuleBaseNameA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_K32GETMODULEBASENAMEA);
		ApiWin->GetModuleHandleA		= (decltype(GetModuleHandleA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETMODULEHANDLEA);
		ApiWin->GetLocalTime			= (decltype(GetLocalTime)*)            GetSymbolAddress(hKernel32Module, HASH_FUNC_GETLOCALTIME);
		ApiWin->GetSystemTimeAsFileTime = (decltype(GetSystemTimeAsFileTime)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_GETSYSTEMTIMEASFILETIME);
		ApiWin->GetProcAddress			= (decltype(GetProcAddress)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETPROCADDRESS);
		ApiWin->GetTickCount			= (decltype(GetTickCount)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETTICKCOUNT);
		ApiWin->GetTimeZoneInformation	= (decltype(GetTimeZoneInformation)*)  GetSymbolAddress(hKernel32Module, HASH_FUNC_GETTIMEZONEINFORMATION);
		ApiWin->HeapAlloc				= (decltype(HeapAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPALLOC);
		ApiWin->HeapCreate				= (decltype(HeapCreate)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPCREATE);
		ApiWin->HeapDestroy				= (decltype(HeapDestroy)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPDESTROY);
		ApiWin->HeapReAlloc				= (decltype(HeapReAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPREALLOC);
		ApiWin->HeapFree				= (decltype(HeapFree)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPFREE);
		ApiWin->InitializeCriticalSection = (decltype(InitializeCriticalSection)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_INITIALIZECRITICALSECTION);
		ApiWin->IsWow64Process			= (decltype(IsWow64Process)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_ISWOW64PROCESS);
		ApiWin->LocalAlloc				= allocProc;
		ApiWin->LocalFree				= (decltype(LocalFree)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_LOCALFREE);
		ApiWin->LocalReAlloc			= (decltype(LocalReAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_LOCALREALLOC);
		ApiWin->LeaveCriticalSection    = (decltype(LeaveCriticalSection)*)    GetSymbolAddress(hKernel32Module, HASH_FUNC_LEAVECRITICALSECTION);
		ApiWin->MoveFileA				= (decltype(MoveFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_MOVEFILEA);
		ApiWin->MultiByteToWideChar		= (decltype(MultiByteToWideChar)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_MULTIBYTETOWIDECHAR);
		ApiWin->PeekNamedPipe			= (decltype(PeekNamedPipe)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_PEEKNAMEDPIPE);
		ApiWin->ReadFile                = (decltype(ReadFile)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_READFILE);
		ApiWin->RemoveDirectoryA        = (decltype(RemoveDirectoryA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_REMOVEDIRECTORYA);
		ApiWin->RtlCaptureContext       = (decltype(RtlCaptureContext)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_RTLCAPTURECONTEXT);
		ApiWin->SetEvent                = (decltype(SetEvent)*)	               GetSymbolAddress(hKernel32Module, HASH_FUNC_SETEVENT);
		ApiWin->ResetEvent              = (decltype(ResetEvent)*)               GetSymbolAddress(hKernel32Module, HASH_FUNC_RESETEVENT);
		ApiWin->SetThreadpoolTimer      = (decltype(SetThreadpoolTimer)*)       GetSymbolAddress(hKernel32Module, HASH_FUNC_SETTHREADPOOLTIMER);
		ApiWin->SetCurrentDirectoryA    = (decltype(SetCurrentDirectoryA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_SETCURRENTDIRECTORYA);
		ApiWin->SetNamedPipeHandleState = (decltype(SetNamedPipeHandleState)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_SETNAMEDPIPEHANDLESTATE);
		ApiWin->Sleep					= (decltype(Sleep)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_SLEEP);
		ApiWin->VirtualAlloc			= (decltype(VirtualAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_VIRTUALALLOC);
		ApiWin->VirtualFree				= (decltype(VirtualFree)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_VIRTUALFREE);
		ApiWin->WaitForSingleObject     = (decltype(WaitForSingleObject)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_WAITFORSINGLEOBJECT);
		ApiWin->WaitNamedPipeA          = (decltype(WaitNamedPipeA)*)	       GetSymbolAddress(hKernel32Module, HASH_FUNC_WAITNAMEDPIPEA);
		ApiWin->WideCharToMultiByte		= (decltype(WideCharToMultiByte)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_WIDECHARTOMULTIBYTE);
		ApiWin->WriteFile				= (decltype(WriteFile)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_WRITEFILE);
		ApiWin->CloseThreadpoolTimer    = (decltype(CloseThreadpoolTimer)*)    GetSymbolAddress(hKernel32Module, HASH_FUNC_CLOSETHREADPOOLTIMER);

		// iphlpapi
		CHAR iphlpapi_c[13];
		iphlpapi_c[0]  = HdChrA('I');
		iphlpapi_c[1]  = HdChrA('p');
		iphlpapi_c[2]  = HdChrA('h');
		iphlpapi_c[3]  = HdChrA('l');
		iphlpapi_c[4]  = HdChrA('p');
		iphlpapi_c[5]  = HdChrA('a');
		iphlpapi_c[6]  = HdChrA('p');
		iphlpapi_c[7]  = HdChrA('i');
		iphlpapi_c[8]  = HdChrA('.');
		iphlpapi_c[9]  = HdChrA('d');
		iphlpapi_c[10] = HdChrA('l');
		iphlpapi_c[11] = HdChrA('l');
		iphlpapi_c[12] = HdChrA(0);
	
		HMODULE hIphlpapiModule = ApiWin->LoadLibraryA(iphlpapi_c);
		SysModules->Iphlpapi = hIphlpapiModule;
		if (hIphlpapiModule) {
			ApiWin->GetAdaptersInfo = (decltype(GetAdaptersInfo)*) GetSymbolAddress(hIphlpapiModule, HASH_FUNC_GETADAPTERSINFO);
		}

		// advapi32
		CHAR advapi32_c[13];
		advapi32_c[0]  = HdChrA('A');
		advapi32_c[1]  = HdChrA('d');
		advapi32_c[2]  = HdChrA('v');
		advapi32_c[3]  = HdChrA('a');
		advapi32_c[4]  = HdChrA('p');
		advapi32_c[5]  = HdChrA('i');
		advapi32_c[6]  = HdChrA('3');
		advapi32_c[7]  = HdChrA('2');
		advapi32_c[8]  = HdChrA('.');
		advapi32_c[9]  = HdChrA('d');
		advapi32_c[10] = HdChrA('l');
		advapi32_c[11] = HdChrA('l');
		advapi32_c[12] = HdChrA(0);

		HMODULE hAdvapi32Module = ApiWin->LoadLibraryA(advapi32_c);
		SysModules->Advapi32 = hAdvapi32Module;
		if (hAdvapi32Module) {
			ApiWin->GetTokenInformation		= (decltype(GetTokenInformation)*)     GetSymbolAddress(hAdvapi32Module, HASH_FUNC_GETTOKENINFORMATION);
			ApiWin->RegisterServiceCtrlHandlerA = (decltype(RegisterServiceCtrlHandlerA)*) GetSymbolAddress(hAdvapi32Module, HASH_FUNC_REGISTERSERVICECTRLHANDLERA);
			ApiWin->SetServiceStatus        = (decltype(SetServiceStatus)*)      GetSymbolAddress(hAdvapi32Module, HASH_FUNC_SETSERVICESTATUS);
			ApiWin->StartServiceCtrlDispatcherA = (decltype(StartServiceCtrlDispatcherA)*) GetSymbolAddress(hAdvapi32Module, HASH_FUNC_STARTSERVICECTRLDISPATCHERA);
			ApiWin->GetUserNameA			= (decltype(GetUserNameA)*)		       GetSymbolAddress(hAdvapi32Module, HASH_FUNC_GETUSERNAMEA);
			ApiWin->LookupAccountSidA		= (decltype(LookupAccountSidA)*)       GetSymbolAddress(hAdvapi32Module, HASH_FUNC_LOOKUPACCOUNTSIDA);
			ApiWin->RevertToSelf			= (decltype(RevertToSelf)*)		       GetSymbolAddress(hAdvapi32Module, HASH_FUNC_REVERTTOSELF );
			ApiWin->SetThreadToken			= (decltype(SetThreadToken)*)		   GetSymbolAddress(hAdvapi32Module, HASH_FUNC_SETTHREADTOKEN);
			ApiWin->ImpersonateLoggedOnUser = (decltype(ImpersonateLoggedOnUser)*) GetSymbolAddress(hAdvapi32Module, HASH_FUNC_IMPERSONATELOGGEDONUSER);
			ApiWin->DuplicateTokenEx        = (decltype(DuplicateTokenEx)*)        GetSymbolAddress(hAdvapi32Module, HASH_FUNC_DUPLICATETOKENEX);
			ApiWin->CreateProcessAsUserA    = (decltype(CreateProcessAsUserA)*)    GetSymbolAddress(hAdvapi32Module, HASH_FUNC_CREATEPROCESSASUSERA);
			ApiWin->CreateProcessWithTokenW = (decltype(CreateProcessWithTokenW)*) GetSymbolAddress(hAdvapi32Module, HASH_FUNC_CREATEPROCESSWITHTOKENW);
		}

		// msvcrt
		CHAR msvcrt_c[11];
		msvcrt_c[0]  = HdChrA('m');
		msvcrt_c[1]  = HdChrA('s');
		msvcrt_c[2]  = HdChrA('v');
		msvcrt_c[3]  = HdChrA('c');
		msvcrt_c[4]  = HdChrA('r');
		msvcrt_c[5]  = HdChrA('t');
		msvcrt_c[6]  = HdChrA('.');
		msvcrt_c[7]  = HdChrA('d');
		msvcrt_c[8]  = HdChrA('l');
		msvcrt_c[9]  = HdChrA('l');
		msvcrt_c[10] = HdChrA(0);

		HMODULE hMsvcrtModule = ApiWin->LoadLibraryA(msvcrt_c);
		SysModules->Msvcrt = hMsvcrtModule;
		if (hMsvcrtModule) {
#if defined(DEBUG)
			ApiWin->printf = (printf_t)GetSymbolAddress(hMsvcrtModule, HASH_FUNC_PRINTF);
#endif
			ApiWin->vsnprintf = (vsnprintf_t) GetSymbolAddress(hMsvcrtModule, HASH_FUNC_VSNPRINTF);
			ApiWin->snprintf   = (snprintf_t) GetSymbolAddress(hMsvcrtModule, HASH_FUNC__SNPRINTF);
		}

		// Ws2_32
		CHAR ws2_32_c[11];
		ws2_32_c[0]  = HdChrA('W');
		ws2_32_c[1]  = HdChrA('s');
		ws2_32_c[2]  = HdChrA('2');
		ws2_32_c[3]  = HdChrA('_');
		ws2_32_c[4]  = HdChrA('3');
		ws2_32_c[5]  = HdChrA('2');
		ws2_32_c[6]  = HdChrA('.');
		ws2_32_c[7]  = HdChrA('d');
		ws2_32_c[8]  = HdChrA('l');
		ws2_32_c[9]  = HdChrA('l');
		ws2_32_c[10] = HdChrA(0);

		HMODULE hWs2_32Module = ApiWin->LoadLibraryA(ws2_32_c);
		SysModules->Ws2_32 = hWs2_32Module;
		if (hWs2_32Module) {
			ApiWin->WSAStartup      = (decltype(WSAStartup)*)      GetSymbolAddress(hWs2_32Module, HASH_FUNC_WSASTARTUP);
			ApiWin->WSACleanup      = (decltype(WSACleanup)*)      GetSymbolAddress(hWs2_32Module, HASH_FUNC_WSACLEANUP);
			ApiWin->WSAGetLastError = (decltype(WSAGetLastError)*) GetSymbolAddress(hWs2_32Module, HASH_FUNC_WSAGETLASTERROR);
			ApiWin->gethostbyname   = (decltype(gethostbyname)*)   GetSymbolAddress(hWs2_32Module, HASH_FUNC_GETHOSTBYNAME);
			ApiWin->socket			= (decltype(socket)*)          GetSymbolAddress(hWs2_32Module, HASH_FUNC_SOCKET);
			ApiWin->ioctlsocket		= (decltype(ioctlsocket)*)     GetSymbolAddress(hWs2_32Module, HASH_FUNC_IOCTLSOCKET);
			ApiWin->connect			= (decltype(connect)*)         GetSymbolAddress(hWs2_32Module, HASH_FUNC_CONNECT);
			ApiWin->setsockopt      = (decltype(setsockopt)*)      GetSymbolAddress(hWs2_32Module, HASH_FUNC_SETSOCKOPT);
			ApiWin->getsockopt	    = (decltype(getsockopt)*)      GetSymbolAddress(hWs2_32Module, HASH_FUNC_GETSOCKOPT);
			ApiWin->closesocket		= (decltype(closesocket)*)     GetSymbolAddress(hWs2_32Module, HASH_FUNC_CLOSESOCKET);
			ApiWin->select			= (decltype(select)*)          GetSymbolAddress(hWs2_32Module, HASH_FUNC_SELECT);
			ApiWin->__WSAFDIsSet    = (decltype(__WSAFDIsSet)*)    GetSymbolAddress(hWs2_32Module, HASH_FUNC___WSAFDISSET);
			ApiWin->shutdown		= (decltype(shutdown)*)        GetSymbolAddress(hWs2_32Module, HASH_FUNC_SHUTDOWN);
			ApiWin->recv     		= (decltype(recv)*)            GetSymbolAddress(hWs2_32Module, HASH_FUNC_RECV);
			ApiWin->recvfrom        = (decltype(recvfrom)*)        GetSymbolAddress(hWs2_32Module, HASH_FUNC_RECVFROM);
			ApiWin->send     		= (decltype(send)*)            GetSymbolAddress(hWs2_32Module, HASH_FUNC_SEND);
			ApiWin->sendto     		= (decltype(sendto)*)          GetSymbolAddress(hWs2_32Module, HASH_FUNC_SENDTO);
			ApiWin->accept     		= (decltype(accept)*)          GetSymbolAddress(hWs2_32Module, HASH_FUNC_ACCEPT);
			ApiWin->listen     		= (decltype(listen)*)          GetSymbolAddress(hWs2_32Module, HASH_FUNC_LISTEN);
			ApiWin->bind     		= (decltype(bind)*)            GetSymbolAddress(hWs2_32Module, HASH_FUNC_BIND);
		}
	}
	else {
		return FALSE;
	}

	if (ApiNt) {
		HMODULE hNtdllModule = GetModuleAddress(HASH_LIB_NTDLL);
		SysModules->Ntdll = hNtdllModule;
		if ( hNtdllModule ) {
			ApiNt->NtClose                   = (decltype(NtClose)*)					  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTCLOSE);
			ApiNt->NtContinue                = (decltype(NtContinue)*)				  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTCONTINUE);
			ApiNt->NtFreeVirtualMemory       = (decltype(NtFreeVirtualMemory)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTFREEVIRTUALMEMORY);
			ApiNt->NtQueryInformationProcess = (decltype(NtQueryInformationProcess)*) GetSymbolAddress(hNtdllModule, HASH_FUNC_NTQUERYINFORMATIONPROCESS);
			ApiNt->NtQuerySystemInformation  = (decltype(NtQuerySystemInformation)*)  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTQUERYSYSTEMINFORMATION);
			ApiNt->NtOpenProcess             = (decltype(NtOpenProcess)*)			  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTOPENPROCESS);
			ApiNt->NtOpenProcessToken        = (decltype(NtOpenProcessToken)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTOPENPROCESSTOKEN);
			ApiNt->NtOpenThreadToken         = (decltype(NtOpenThreadToken)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTOPENTHREADTOKEN);
			ApiNt->NtTerminateThread         = (decltype(NtTerminateThread)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTTERMINATETHREAD);
			ApiNt->NtTerminateProcess        = (decltype(NtTerminateProcess)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTTERMINATEPROCESS);
			ApiNt->RtlGetVersion             = (decltype(RtlGetVersion)*)			  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLGETVERSION);
			ApiNt->RtlExitUserThread         = (decltype(RtlExitUserThread)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLEXITUSERTHREAD);
			ApiNt->RtlExitUserProcess        = (decltype(RtlExitUserProcess)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLEXITUSERPROCESS);
			ApiNt->RtlIpv4StringToAddressA   = (decltype(RtlIpv4StringToAddressA)*)	  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLIPV4STRINGTOADDRESSA);
			ApiNt->RtlRandomEx               = (decltype(RtlRandomEx)*)				  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLRANDOMEX);
			ApiNt->RtlNtStatusToDosError     = (decltype(RtlNtStatusToDosError)*)	  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLNTSTATUSTODOSERROR);
		}
		else {
			return FALSE;
		}
	}
	else {
		return FALSE;
	}
	return TRUE;
}
#endif
