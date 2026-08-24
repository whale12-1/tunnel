#include <chrono>
#include <random>
#include <iostream>
#include <cstdlib>

extern "C" {
#include "lwip/opt.h"

    // 1. Системное время (миллисекунды от старта программы) — единственное, что нужно lwIP в NO_SYS = 1
    u32_t sys_now(void) {
        static auto start = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        return static_cast<u32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count());
    }

    // 2. Генератор случайных чисел для TCP Initial Sequence Number
    u32_t lwip_port_rand(void) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<u32_t> dis;
        return dis(gen);
    }

    // 3. Обработчик ассертов lwIP
    void lwip_example_app_platform_assert(const char* msg, int line, const char* file) {
        std::cerr << "[lwIP Assert] " << msg << " at " << file << ":" << line << "\n";
        std::abort();
    }

} // extern "C"