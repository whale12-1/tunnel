#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <memory>
#include "CryptoEngine.h"

namespace Vpn::Server {

    struct ServerConfig {
        uint16_t port = 18080;
        std::vector<uint8_t> privateKey;
        std::string sniFallback = "dl.google.com";
    };

    class ConfigManager {
    public:
        static ServerConfig LoadOrInit(const std::string& configPath, uint16_t defaultPort) {
            ServerConfig config;
            config.port = defaultPort;
            bool keyLoaded = false;

            // 1. Приоритет: Переменная окружения VPN_PRIVATE_KEY (в Base64)
            if (const char* envKey = std::getenv("VPN_PRIVATE_KEY")) {
                config.privateKey = CryptoEngine::Base64Decode(envKey);
                if (config.privateKey.size() == 32) {
                    std::cout << "[Config] Loaded private key from environment variable.\n";
                    keyLoaded = true;
                }
                else {
                    std::cerr << "[Config Warning] Invalid key in ENV. Falling back to file...\n";
                }
            }

            // 2. Приоритет: Текстовый файл конфигурации
            if (!keyLoaded) {
                std::ifstream inFile(configPath);
                if (inFile.is_open()) {
                    std::string keyBase64;
                    if (inFile >> keyBase64) {
                        config.privateKey = CryptoEngine::Base64Decode(keyBase64);
                        if (config.privateKey.size() == 32) {
                            std::cout << "[Config] Loaded private key from " << configPath << "\n";
                            keyLoaded = true;
                        }
                    }
                    if (!keyLoaded) {
                        std::cerr << "[Config Warning] Corrupted key file. Re-generating identity...\n";
                    }
                }
            }

            std::unique_ptr<CryptoEngine> tempEngine;

            // 3. Автогенерация (Первый запуск или файл поврежден)
            if (!keyLoaded) {
                tempEngine = std::make_unique<CryptoEngine>();
                config.privateKey = tempEngine->GetLocalPrivateKey();

                std::string privBase64 = CryptoEngine::Base64Encode(config.privateKey);
                std::ofstream outFile(configPath);
                if (outFile.is_open()) {
                    outFile << privBase64 << "\n";
                    std::cout << "[Config] Saved new identity to " << configPath << "\n";
                }
            }
            else {
                tempEngine = std::make_unique<CryptoEngine>(config.privateKey);
            }

            // --- Генерация client.conf для локального тестирования ---
            auto pubKey = tempEngine->GetLocalPublicKey();
            std::string pubBase64 = CryptoEngine::Base64Encode(pubKey);

            std::ofstream clientConf("client.conf");
            if (clientConf.is_open()) {
                clientConf << "vpn://" << pubBase64 << "@<YOUR_SERVER_IP>:" << config.port << "?sni=" << config.sniFallback << "\n";
                std::cout << "[Config] Generated client.conf for local testing.\n";
            }

            PrintClientConnectionInfo(pubBase64, config.port, config.sniFallback);

            return config;
        }

    private:
        static void PrintClientConnectionInfo(const std::string& pubKeyBase64, uint16_t port, const std::string& sni) {
            std::cout << "\n======================================================\n";
            std::cout << "[SERVER IDENTITY]\n";
            std::cout << "Public Key (Base64): " << pubKeyBase64 << "\n";
            std::cout << "Client Connection URI:\n";
            std::cout << "  vpn://" << pubKeyBase64 << "@<YOUR_SERVER_IP>:" << port << "?sni=" << sni << "\n";
            std::cout << "======================================================\n\n";
        }
    };

} // namespace Vpn::Server