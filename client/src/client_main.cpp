#include <boost/asio.hpp>
#include <iostream>
#include "LocalProxyListener.cpp"
#include "VpnTransport.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <fstream>
#include <vector>
#include <stdexcept>

// Функция для автоматического чтения ключа
std::vector<uint8_t> LoadServerPublicKey(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open server_pub.key. Start the server first!");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> key(size);
    if (!file.read(reinterpret_cast<char*>(key.data()), size)) {
        throw std::runtime_error("Failed to read server public key data.");
    }
    return key;
}

int main() {
    std::cout << std::unitbuf;
#ifdef _WIN32
    SetThreadUILanguage(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    try {
        boost::asio::io_context ioContext;

        // 1. Автоматически подгружаем актуальный ключ сервера из файла
        std::vector<uint8_t> serverPublicKey = LoadServerPublicKey("server_pub.key");

        // 2. Создаем транспорт, передавая загруженный ключ
        auto vpnTransport = std::make_shared<Vpn::Client::VpnTransport>(ioContext, "127.0.0.1", 8080, serverPublicKey);

        // 3. Запускаем локальный SOCKS5 слушатель
        auto listener = std::make_shared<Vpn::Client::LocalProxyListener>(ioContext, 1080, vpnTransport);
        listener->Start();
        std::cout << "[VPN Client] SOCKS5 proxy listening on 127.0.0.1:1080\n";

        // 4. Подключаемся
        vpnTransport->Connect([](bool success) {
            if (!success) {
                std::cerr << "[VPN Client Warning] Could not connect to VPN server right now. Retrying later...\n";
            }
            });

        ioContext.run();
    }
    catch (const std::exception& e) {
        std::cerr << "[VPN Client Error]: " << e.what() << std::endl;
    }

    return 0;
}