# DLL initialization process

This document records only the technical initialization sequence used by the DLL build.

## Entry points involved

The DLL initialization path uses these routines:

- `DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)`
- `InitializeSynchronization()`
- `CreateThreadpoolTimer()`
- `SetThreadpoolTimer()`
- `InitializationCallback(PTP_CALLBACK_INSTANCE, PVOID, PTP_TIMER)`
- `run()`
- `AgentMain()`
- `GetVersions(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)`

## Automatic initialization flow

Initialization is guarded so it runs only once per process.

1. `DllMain` receives `DLL_PROCESS_ATTACH`.
2. `InitializeSynchronization()` initializes the internal synchronization state.
3. `DllMain` creates a thread-pool timer with `CreateThreadpoolTimer()`.
4. The timer is scheduled immediately with `SetThreadpoolTimer()`.
5. `InitializationCallback()` runs from the timer callback context.
6. `InitializationCallback()` closes the timer handle.
7. `InitializationCallback()` calls `run()`.
8. `run()` uses `InterlockedCompareExchange()` on `g_AgentInitialized`.
9. If `g_AgentInitialized` was previously unset, `run()` marks initialization as complete.
10. `run()` creates a detached thread whose start routine is `AgentMain`.
11. `AgentMain()` performs API loading.
12. `AgentMain()` creates the global runtime state.
13. `AgentMain()` creates the protocol-specific connector.
14. `AgentMain()` initializes asynchronous BOF handling.
15. `AgentMain()` builds the first beat.
16. `AgentMain()` applies the connector profile.
17. `AgentMain()` enters the connection and task loop.

The thread-pool timer defers heavier work out of `DllMain`, avoiding that work while the Windows loader lock is held.

## One-shot guard

`g_AgentInitialized` is the shared one-shot guard for initialization.

`run()` calls:

```cpp
InterlockedCompareExchange(&g_AgentInitialized, TRUE, FALSE)
```

Only the caller that observes the previous value as `FALSE` starts `AgentMain`. Later callers observe that initialization has already happened and return without starting another thread.

## Exported initialization path

`GetVersions` provides a second path into the same initialization logic.

1. `GetVersions` calls `InitializeSynchronization()`.
2. It attempts to set `g_AgentInitialized` from `FALSE` to `TRUE`.
3. If the transition succeeds, it creates a thread whose start routine is `AgentMain`.
4. It waits for that thread with `WaitForSingleObject()` before returning.
5. If initialization already occurred, it does not start another thread.

Because `GetVersions` and `run()` share `g_AgentInitialized`, both paths are mutually exclusive.

## Detach handling related to initialization state

On `DLL_PROCESS_DETACH`, `DllMain` deletes the critical section only when both conditions are true:

- The detach is not process termination: `lpReserved == NULL`.
- The synchronization state was initialized.
