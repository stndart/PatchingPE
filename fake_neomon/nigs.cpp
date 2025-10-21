#include <cstdio>
#include <cstring>
#include <windows.h>

extern "C" {

// Returns 0x101010 in EAX
__declspec(dllexport) int __stdcall NIGS_1() { return 0x101010; }

// Sets EAX = 0 and ECX = 0x932F42C7
__declspec(dllexport) int __stdcall NIGS_2() {
  __asm {
        mov ecx, 0x932F42C7
  }
  return 0;
}
}

void InitializeMyStuff() {
  // replace 0xa0f2f0 from FF 15 E0 88 58 01 with 47 E1 62 02
  // replace 0xa0f368 from FF 15 EC 88 58 01 with 4B E1 62 02

  BYTE *addr1 = reinterpret_cast<BYTE *>(0x00A0F2F0);
  BYTE *addr2 = reinterpret_cast<BYTE *>(0x00A0F368);

  BYTE patch1[] = {0xFF, 0x15, 0x47, 0xE1, 0x62, 0x02};
  BYTE patch2[] = {0xFF, 0x15, 0x4B, 0xE1, 0x62, 0x02};

  // std::memcpy(addr1, patch1, sizeof(patch1));
  // std::memcpy(addr2, patch2, sizeof(patch2));

  // printf("Patched");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    CreateThread(
        nullptr, 0,
        [](LPVOID) -> DWORD {
          Sleep(200); // wait 2 seconds for other DLLs to initialize
          InitializeMyStuff();
          return 0;
        },
        nullptr, 0, nullptr);
  }
  return TRUE;
}
