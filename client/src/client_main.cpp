#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "WintunTunnel.h"
#endif

#include "LocalProxyListener.cpp"
#include "VpnTransport.h"

struct ClientConfig {
    std::string serverIp = "127.0.0.1";
    uint16_t serverPort = 18080;
    std::vector<uint8_t> serverPublicKey;
    std::string sniHost = "dl.google.com";
    uint16_t localSocksPort = 1080;
};

std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string UrlDecode(const std::string& src) {
    std::string dst;
    for (size_t i = 0; i < src.length(); ++i) {
        if (src[i] == '%' && i + 2 < src.length()) {
            try {
                int v = std::stoi(src.substr(i + 1, 2), nullptr, 16);
                dst += static_cast<char>(v);
                i += 2;
                continue;
            }
            catch (...) {}
        }
        dst += src[i];
    }
    return dst;
}

std::vector<uint8_t> Base64Decode(std::string in) {
    // Поддержка URL-safe Base64
    for (char& c : in) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }

    std::vector<uint8_t> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    unsigned int val = 0; // Изменено на unsigned int для избежания UB
    int valb = -8;

    for (uint8_t c : in) {
        if (c == '=') break; // Явно останавливаемся только на символе выравнивания
        if (T[c] == -1) continue; // Игнорируем мусор (\r, \n, пробелы) вместо полного сброса

        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(uint8_t((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

ClientConfig ParseVpnUri(const std::string& uri) {
    ClientConfig cfg;
    std::string rest = uri;

    size_t schemePos = rest.find("vpn://");
    if (schemePos != std::string::npos) {
        rest = rest.substr(schemePos + 6);
    }

    size_t atPos = rest.find('@');
    size_t questionPos = rest.find('?');

    // Ищем порт ТОЛЬКО после '@' (если он есть), чтобы защититься от двоеточий внутри ключа
    size_t colonSearchStart = (atPos != std::string::npos) ? atPos : 0;
    size_t colonPos = rest.find(':', colonSearchStart);

    // Если двоеточие нашлось, но оно находится в параметрах запроса после '?' — игнорируем его
    if (colonPos != std::string::npos && questionPos != std::string::npos && colonPos > questionPos) {
        colonPos = std::string::npos;
    }

    if (atPos != std::string::npos) {
        std::string keyRaw = rest.substr(0, atPos);
        cfg.serverPublicKey = Base64Decode(UrlDecode(keyRaw)); // Применяем UrlDecode к ключу

        size_t ipEnd = (colonPos != std::string::npos) ? colonPos :
            (questionPos != std::string::npos ? questionPos : rest.length());
        cfg.serverIp = rest.substr(atPos + 1, ipEnd - atPos - 1);
    }
    else {
        size_t ipEnd = (colonPos != std::string::npos) ? colonPos :
            (questionPos != std::string::npos ? questionPos : rest.length());
        cfg.serverIp = rest.substr(0, ipEnd);
    }

    if (colonPos != std::string::npos) {
        size_t portEnd = (questionPos != std::string::npos) ? questionPos : rest.length();
        try {
            cfg.serverPort = static_cast<uint16_t>(std::stoi(rest.substr(colonPos + 1, portEnd - colonPos - 1)));
        }
        catch (...) {}
    }

    if (questionPos != std::string::npos) {
        std::string query = rest.substr(questionPos + 1);
        size_t sniPos = query.find("sni=");
        if (sniPos != std::string::npos) {
            size_t ampPos = query.find('&', sniPos);
            std::string sniRaw = query.substr(sniPos + 4, ampPos != std::string::npos ? ampPos - (sniPos + 4) : std::string::npos);
            cfg.sniHost = UrlDecode(sniRaw); // Применяем UrlDecode к SNI
        }
    }

    if (cfg.serverIp.empty() || cfg.serverIp.find("<YOUR_SERVER_IP>") != std::string::npos || cfg.serverIp == "YOUR_SERVER_IP") {
        cfg.serverIp = "127.0.0.1";
    }

    return cfg;
}
ClientConfig LoadConfiguration(int argc, char* argv[]) {
    ClientConfig cfg;
    bool loadedFromUri = false;

    if (argc > 1) {
        std::string arg1 = Trim(argv[1]);
        if (arg1.rfind("vpn://", 0) == 0) {
            std::cout << "[Config] Using URI from command line argument.\n";
            cfg = ParseVpnUri(arg1);
            loadedFromUri = true;
        }
    }

    if (!loadedFromUri) {
        std::ifstream clientConf("client.conf");
        if (clientConf.is_open()) {
            std::string line;
            while (std::getline(clientConf, line)) {
                line = Trim(line);
                if (line.rfind("vpn://", 0) == 0) {
                    std::cout << "[Config] Using URI from client.conf.\n";
                    cfg = ParseVpnUri(line);
                    loadedFromUri = true;
                    break;
                }
            }
        }
    }

    // Если публичный ключ не был передан в URI, пробуем подгрузить из файла server_pub.key
    if (cfg.serverPublicKey.empty()) {
        std::ifstream keyFile("server_pub.key", std::ios::binary | std::ios::ate);
        if (keyFile.is_open()) {
            std::cout << "[Config] Fallback: Loading key from server_pub.key...\n";
            std::streamsize size = keyFile.tellg();
            keyFile.seekg(0, std::ios::beg);
            cfg.serverPublicKey.resize(size);
            keyFile.read(reinterpret_cast<char*>(cfg.serverPublicKey.data()), size);
        }
        else {
            std::cerr << "[Config Warning] Public key missing in URI and no fallback server_pub.key found.\n";
        }
    }

    return cfg;
}

int main(int argc, char* argv[]) {
    std::cout << std::unitbuf;
#ifdef _WIN32
    SetThreadUILanguage(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    try {
        boost::asio::io_context ioContext;

        ClientConfig config = LoadConfiguration(argc, argv);

        if (config.serverPublicKey.empty()) {
            throw std::runtime_error("Server public key is missing! Provide URI with key or server_pub.key.");
        }

        std::cout << "[VPN Client] Target Server: " << config.serverIp << ":" << config.serverPort
            << " | SNI: " << config.sniHost << "\n";

        auto vpnTransport = std::make_shared<Vpn::Client::VpnTransport>(
            ioContext, config.serverIp, config.serverPort, config.serverPublicKey, config.sniHost
        );

        auto listener = std::make_shared<Vpn::Client::LocalProxyListener>(ioContext, config.localSocksPort, vpnTransport);
        listener->Start();
        std::cout << "[VPN Client] SOCKS5 proxy listening on 127.0.0.1:" << config.localSocksPort << "\n";

#ifdef _WIN32
        auto wintunTunnel = std::make_shared<Vpn::Client::WintunTunnel>(ioContext, vpnTransport);
#endif

        vpnTransport->Connect([&ioContext, config
#ifdef _WIN32
            , wintunTunnel
#endif
        ](bool success) {
                if (!success) {
                    std::cerr << "[VPN Client Warning] Initial connection to VPN server failed. Retrying in background...\n";
                    return;
                }

                std::cout << "[VPN Client] Connected to VPN Server successfully!\n";

#ifdef _WIN32
                bool isLocalhost = (config.serverIp == "127.0.0.1" || config.serverIp == "localhost" || config.serverIp == "::1");

                if (!isLocalhost) {
                    if (wintunTunnel->InitAdapter(L"CustomVPN")) {
                        wintunTunnel->Start();
                        wintunTunnel->SetupRouting(config.serverIp);
                        std::cout << "[VPN Client] Wintun full system tunnel started successfully!\n";
                    }
                    else {
                        std::cout << "[VPN Client Warning] Running without Wintun adapter (Fallback to SOCKS5 only).\n";
                    }
                }
                else {
                    std::cout << "[VPN Client Info] Local testing mode detected (" << config.serverIp
                        << "). Wintun disabled to prevent routing loops. Use SOCKS5 (127.0.0.1:"
                        << config.localSocksPort << ").\n";
                }
#endif
            });

        ioContext.run();
    }
    catch (const std::exception& e) {
        std::cerr << "[VPN Client Error]: " << e.what() << std::endl;
    }

    return 0;
}