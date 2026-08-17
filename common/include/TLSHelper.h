#pragma once
#include <vector>
#include <string>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace Vpn::Protocol {

    class ReplayCache {
    public:
        // Проверяет, встречался ли HMAC. Если да — возвращает true (Replay!).
        // Если нет — сохраняет его и возвращает false.
        static bool IsReplayAndInsert(const std::vector<uint8_t>& sessionIdPrefix, uint32_t ttlSeconds = 60) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto now = std::chrono::steady_clock::now();

            // 1. Периодическая очистка просроченных записей (каждые 30 сек)
            static auto lastCleanup = now;
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastCleanup).count() > 30) {
                for (auto it = m_cache.begin(); it != m_cache.end(); ) {
                    if (now > it->second) {
                        it = m_cache.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
                lastCleanup = now;
            }

            std::string key(sessionIdPrefix.begin(), sessionIdPrefix.end());

            // 2. Проверка наличия в кэше
            auto it = m_cache.find(key);
            if (it != m_cache.end() && now < it->second) {
                return true; // Это REPLAY!
            }

            // 3. Сохраняем в кэш с моментом истечения TTL
            m_cache[key] = now + std::chrono::seconds(ttlSeconds);
            return false;
        }

    private:
        static inline std::mutex m_mutex;
        static inline std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_cache;
    };

    class TlsHelper {
    public:
        // Сборка полноценного ClientHello (Chrome Fingerprint + Padding до 512 байт + REALITY HMAC)
        static std::vector<uint8_t> BuildClientHello(
            const std::string& sni,
            const std::vector<uint8_t>& clientPubKey,
            const std::vector<uint8_t>& serverPublicKey
        );

        // Валидация REALITY HMAC и динамический разбор расширений из 512-байтового ClientHello
        static bool VerifyAndParseClientHello(
            const std::vector<uint8_t>& packet,
            const std::vector<uint8_t>& serverPublicKey,
            std::vector<uint8_t>& outClientPubKey,
            std::string& outSni
        );

        // Извлечение SNI при некорректном HMAC (для перенаправления пассивного/активного сканера на настоящий сайт)
        static bool ParseSniFromClientHello(
            const std::vector<uint8_t>& packet,
            std::string& outSni
        );

        // Сборка ServerHello (TLS 1.3 RFC 8446)
        static std::vector<uint8_t> BuildServerHello(
            const std::vector<uint8_t>& serverPubKey,
            const std::vector<uint8_t>& clientSessionId
        );

        // Извлечение публичного ключа сервера на клиенте
        static bool ParseServerHello(
            const std::vector<uint8_t>& packet,
            std::vector<uint8_t>& outServerPubKey
        );
        static std::vector<uint8_t> BuildFakeTls13HandshakePayload(size_t targetTotalSize = 2800);

    private:
        static std::vector<uint8_t> ComputeHmacSha256(
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& data
        );
    };

} // namespace Vpn::Protocol