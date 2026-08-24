#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Архитектурные типы lwIP
typedef uint8_t   u8_t;
typedef int8_t    s8_t;
typedef uint16_t  u16_t;
typedef int16_t   s16_t;
typedef uint32_t  u32_t;
typedef int32_t   s32_t;

typedef uintptr_t mem_ptr_t;

// Спецификаторы форматного вывода для printf
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"

// Упаковка структур для компиляторов MSVC / GCC / Clang
#if defined(_MSC_VER)
#define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
#define PACK_STRUCT_END   __pragma(pack(pop))
#define PACK_STRUCT_STRUCT
#else
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END
#define PACK_STRUCT_STRUCT __attribute__((packed))
#endif

// Платформенные макросы отладки и ассертов
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { printf("Assertion \"%s\" failed at line %d in %s\n", x, __LINE__, __FILE__); abort(); } while(0)