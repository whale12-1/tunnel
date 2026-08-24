#include <boost/asio.hpp>
#include <iostream>
#include "Server.h"

int main() {
#ifdef _WIN32
    // Force English (US) for Windows system error messages (ec.message())
    SetThreadUILanguage(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));

    // Force UTF-8 for console output
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    try {
        boost::asio::io_context ioContext;

        // Слушаем порт 8080 для входящих VPN-клиентов
        Vpn::Server::Server server(ioContext, 18080);
        server.Start();

        std::cout << "[VPN Server] Started on port 18080..." << std::endl;
        ioContext.run();
    }
    catch (const std::exception& e) {
        std::cerr << "[VPN Server Error]: " << e.what() << std::endl;
    }
    return 0;
}