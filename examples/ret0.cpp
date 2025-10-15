#include <iostream>
#include <thread>

int main() {
  std::cout << 0 << std::endl;
  std::this_thread::sleep_for(std::chrono::seconds(10));
  return 0;
}