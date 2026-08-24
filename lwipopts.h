#pragma once

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                  1   // Включаем режим без ОС (RAW API)
#define LWIP_SOCKET             0   // Отключаем BSD-сокеты (они не нужны для tun2socks)
#define LWIP_NETCONN            0   // Отключаем Netconn API

#define LWIP_TCP                1
#define LWIP_UDP                1   // Обязательно включено
#define LWIP_IPV4               1   // Обязательно для IPv4              1   // <--- Включаем поддержку UDP протокола

#define SYS_LIGHTWEIGHT_PROT    0   // Защита критических секций не нужна в однопоточном Asio

#define MEM_ALIGNMENT           4
#define MEM_SIZE                (16 * 1024)
#define MEMP_NUM_TCP_PCB        32
#define MEMP_NUM_TCP_PCB_LISTEN 16
#define MEMP_NUM_TCP_SEG        64
#define TCP_MSS                 1460
#define TCP_SND_BUF             (4 * TCP_MSS)
#define TCP_WND                 (4 * TCP_MSS)

#endif /* LWIPOPTS_H */