#include "Server.h"
#include "ConfigManager.h"
#include "Session.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>

#ifndef _WIN32
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace Vpn::Server {

    // јвтоматическое определение IP-адреса WSL (eth0)
    static std::string GetWslIp() {
        std::string detectedIp = "127.0.0.1";
#ifndef _WIN32
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == 0) {
            for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                    std::string ifName = ifa->ifa_name;
                    if (ifName != "lo") {
                        void* tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                        char addressBuffer[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                        detectedIp = addressBuffer;

                        if (ifName == "eth0") {
                            break;
                        }
                    }
                }
            }
            freeifaddrs(ifaddr);
        }
#endif
        return detectedIp;
    }

    Server::Server(boost::asio::io_context& ioContext, uint16_t port)
        : m_ioContext(ioContext),
        m_acceptor(ioContext, tcp::endpoint(boost::asio::ip::make_address("0.0.0.0"), port))
    {
        // «агружаем или инициализируем конфиг
        ServerConfig config = ConfigManager::LoadOrInit("server_identity.conf", port);

        m_serverCrypto = std::make_shared<CryptoEngine>(config.privateKey);

        // --- ƒ»Ќјћ»„≈— јя —»Ќ’–ќЌ»«ј÷»я client.conf ¬ WINDOWS ---
        namespace fs = std::filesystem;
        fs::path srcFile = "client.conf";

        // ѕути к папке отладки и к корню проекта в Windows
        std::vector<fs::path> winTargetDirs = {
            "/mnt/c/Users/Lenovo/source/repos/customvpn/out/build/x64-Debug/Debug",
            "/mnt/c/Users/Lenovo/source/repos/customvpn"
        };

        if (fs::exists(srcFile)) {
            std::ifstream src(srcFile);
            if (src.is_open()) {
                std::string content((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
                src.close();

                std::string wslIp = GetWslIp();

                // »щем позицию @ и следующего за ним : чтобы динамически заменить любой IP
                size_t atPos = content.find('@');
                size_t colonPos = content.find(':', atPos != std::string::npos ? atPos : 0);

                if (atPos != std::string::npos && colonPos != std::string::npos && colonPos > atPos) {
                    content.replace(atPos + 1, colonPos - atPos - 1, wslIp);
                }
                else if (size_t pos = content.find("<YOUR_SERVER_IP>"); pos != std::string::npos) {
                    content.replace(pos, 16, wslIp);
                }

                // ѕерезаписываем скорректированный конфиг обратно в WSL
                std::ofstream localDst(srcFile, std::ios::trunc);
                if (localDst.is_open()) {
                    localDst << content;
                    localDst.close();
                }

                // Ёкспортируем во все потенциальные рабочие директории Windows
                for (const auto& winDir : winTargetDirs) {
                    if (fs::exists(winDir)) {
                        std::ofstream dst(winDir / "client.conf", std::ios::trunc);
                        if (dst.is_open()) {
                            dst << content;
                            std::cout << "[Config] Synced client.conf (" << wslIp << ") -> " << winDir.filename().string() << "\n";
                        }
                    }
                }
            }
        }
    }

    void Server::Start() {
        DoAccept();
    }

    void Server::DoAccept() {
        m_acceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::cout << "[Server] Incoming TCP connection from: "
                        << socket.remote_endpoint().address().to_string() << ":"
                        << socket.remote_endpoint().port() << std::endl;
                    std::make_shared<Session>(std::move(socket), m_serverCrypto)->Start();
                }
                else {
                    std::cerr << "[Server ERROR] Accept failed: " << ec.message() << std::endl;
                }
                DoAccept();
            }
        );
    }

} // namespace Vpn::Server