#define _X86_
#include <iostream>
#include <windows.h>

// Forward declaration of the function from DLL
extern "C" __declspec(dllimport) int NIGS_1();
extern "C" __declspec(dllimport) int NIGS_2();
extern "C" __declspec(dllimport) int NIGS_3();
extern "C" __declspec(dllimport) int NIGS_4();
extern "C" __declspec(dllimport) int NIGS_5();
extern "C" __declspec(dllimport) int NIGS_6();
extern "C" __declspec(dllimport) int NIGS_7();

int main() {
  std::cout << "DLL will load automatically due to implicit linking..."
            << std::endl;
  std::cout << "Set breakpoint here - DLL should be unpacked by now!"
            << std::endl;

  std::cout << "Press Enter to call functions..." << std::endl;
  std::cin.get();

  int N = 1;
  int (*fs[])() = {
      NIGS_1, NIGS_2, NIGS_3, NIGS_4, NIGS_5, NIGS_6, NIGS_7,
  };
  for (size_t i = 1; i <= N; ++i) {
    int a = fs[i - 1]();
    std::cout << "Function NIGS_" << i << " called successfully: " << std::hex
              << a << std::endl;
  }
  std::cout << "Press Enter to run a loop..." << std::endl;
  std::cin.get();

  size_t M = 10;
  for (size_t i = 0; i < M; ++i)
    Sleep(1000);

  std::cout << "Loop ended successfully!" << std::endl;
  std::cout << "Press Enter to exit..." << std::endl;
  std::cin.get();

  return 0;
}