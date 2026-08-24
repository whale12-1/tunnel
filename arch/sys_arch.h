#pragma once

#ifdef __cplusplus
extern "C" {
#endif

	// Базовые системные типы-заглушки для lwIP в однопоточном/Asio окружении
	typedef void* sys_sem_t;
	typedef void* sys_mutex_t;
	typedef void* sys_mbox_t;
	typedef unsigned long sys_thread_t;
	typedef int sys_prot_t;

#ifdef __cplusplus
}
#endif