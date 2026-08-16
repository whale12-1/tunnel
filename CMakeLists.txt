cmake_minimum_required(VERSION 3.20)
project(CustomVPN CXX)

# --- БАЗОВЫЕ НАСТРОЙКИ C++ ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/std:c++20 /utf-8)
endif()

# Опции сборки компонентов
option(BUILD_SERVER "Build VPN Server executable" ON)
option(BUILD_GUI    "Build Qt GUI Client executable" ON)

# --- НАСТРОЙКА ПУТЕЙ ВЫВОДА ---
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug")

# --- ПОИСК BOOST (Header-Only для Asio) ---
if(WIN32)
    set(BOOST_ROOT "C:/boost/boost")
    set(BOOST_INCLUDEDIR "C:/boost/boost")
    set(BOOST_LIBRARYDIR "C:/boost/boost/stage/lib")
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_MULTITHREADED ON)
endif()

# Отключаем предупреждение CMake о "слишком новой версии Boost"
set(Boost_NO_WARN_NEW_VERSIONS ON)

# Ищем Boost (Header-Only)
find_package(Boost REQUIRED)

# --- ПОИСК OPENSSL ---
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/OpenSSL-Win64")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.lib")
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libssl.lib")

    if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.lib")
        set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libssl.lib")
    endif()
else()
    find_package(OpenSSL REQUIRED)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_CRYPTO_LIBRARY OpenSSL::Crypto)
    set(OPENSSL_SSL_LIBRARY OpenSSL::SSL)
endif()

# --- ПОИСК QT6 (ДЛЯ GUI) ---
if(BUILD_GUI)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_AUTORCC ON)
    find_package(Qt6 REQUIRED COMPONENTS Widgets Network)
endif()


# --- 1. ТАРГЕТ: vpn_core (Статическая библиотека) ---
# Автоматически включает все .cpp и .h файлы из common/ и core/ (включая TlsHelper)
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/common/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.h"
)

add_library(vpn_core STATIC ${CORE_SOURCES})

target_compile_features(vpn_core PUBLIC cxx_std_20)

target_include_directories(vpn_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/common/include
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(vpn_core PUBLIC 
    "${OPENSSL_CRYPTO_LIBRARY}"
    "${OPENSSL_SSL_LIBRARY}"
)

if(WIN32)
    target_link_libraries(vpn_core PRIVATE ws2_32 iphlpapi mswsock)
    target_include_directories(vpn_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wintun)
elseif(UNIX)
    target_link_libraries(vpn_core PRIVATE pthread)
endif()


# --- 2. ТАРГЕТ: vpn_server (Исполняемый файл сервера) ---
if(BUILD_SERVER)
    file(GLOB_RECURSE SERVER_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/server/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/server/*.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/server/*.h"
    )

    add_executable(vpn_server ${SERVER_SOURCES})
    target_include_directories(vpn_server PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/server
        ${CMAKE_CURRENT_SOURCE_DIR}/server/include
    )
    target_link_libraries(vpn_server PRIVATE vpn_core)
endif()


# --- 3. ТАРГЕТ: vpn_gui (Qt Графический клиент) ---
if(BUILD_GUI)
    file(GLOB_RECURSE GUI_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/gui/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/gui/*.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/gui/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/gui/*.ui"
        "${CMAKE_CURRENT_SOURCE_DIR}/gui/*.qrc"
    )

    add_executable(vpn_gui ${GUI_SOURCES})
    target_include_directories(vpn_gui PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/gui
        ${CMAKE_CURRENT_SOURCE_DIR}/gui/include
    )
    
    target_link_libraries(vpn_gui PRIVATE 
        vpn_core 
        Qt6::Widgets 
        Qt6::Network
    )

    if(WIN32)
        set_target_properties(vpn_gui PROPERTIES WIN32_EXECUTABLE ON)

        set(OPENSSL_BIN_DIR "${OPENSSL_ROOT_DIR}/bin")
        add_custom_command(TARGET vpn_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_BIN_DIR}/libcrypto-4-x64.dll"
            "${OPENSSL_BIN_DIR}/libssl-4-x64.dll"
            "$<TARGET_FILE_DIR:vpn_gui>"
            COMMENT "Copying OpenSSL DLLs..."
        )
    endif()

    if(DEFINED VCPKG_INSTALLED_DIR)
        set(QT_PLUGINS_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/qt6/plugins")
        if(NOT EXISTS "${QT_PLUGINS_DIR}/platforms")
            set(QT_PLUGINS_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/qt6/plugins")
        endif()

        add_custom_command(TARGET vpn_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${QT_PLUGINS_DIR}/platforms"
            "$<TARGET_FILE_DIR:vpn_gui>/platforms"
            COMMENT "Copying Qt platform plugins..."
        )
    endif()
endif()


# --- 4. ТАРГЕТ: vpn_cli_client (Консольный клиент) ---
file(GLOB_RECURSE CLIENT_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/client/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/client/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/client/*.h"
)

add_executable(vpn_cli_client ${CLIENT_SOURCES})

target_include_directories(vpn_cli_client PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/client
    ${CMAKE_CURRENT_SOURCE_DIR}/client/include
)

target_link_libraries(vpn_cli_client PRIVATE vpn_core)


# --- ПОСТ-СБОРКА ДЛЯ WINDOWS (Автокопирование OpenSSL DLL) ---
if(WIN32)
    set(OPENSSL_BIN_DIR "${OPENSSL_ROOT_DIR}/bin")

    if(TARGET vpn_server)
        add_custom_command(TARGET vpn_server POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_BIN_DIR}/libcrypto-4-x64.dll"
            "${OPENSSL_BIN_DIR}/libssl-4-x64.dll"
            "$<TARGET_FILE_DIR:vpn_server>"
            COMMENT "Copying OpenSSL DLLs for vpn_server..."
        )
    endif()

    if(TARGET vpn_cli_client)
        add_custom_command(TARGET vpn_cli_client POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_BIN_DIR}/libcrypto-4-x64.dll"
            "${OPENSSL_BIN_DIR}/libssl-4-x64.dll"
            "$<TARGET_FILE_DIR:vpn_cli_client>"
            COMMENT "Copying OpenSSL DLLs for vpn_cli_client..."
        )
    endif()
endif()