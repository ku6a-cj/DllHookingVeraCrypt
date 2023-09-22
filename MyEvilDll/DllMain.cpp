// system includes
#include <Windows.h>

// custom includes
#include "evil.h"

BOOL
APIENTRY
DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{ 
    BeginHook();
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
       
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

