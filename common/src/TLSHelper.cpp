#include "TlsHelper.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <ctime>  // Для std::time
#include <cmath>  // Для std::abs

namespace Vpn::Protocol {


    std::vector<uint8_t> TlsHelper::ComputeHmacSha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hmac(32);
        unsigned int len = 0;
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
            data.data(), data.size(), hmac.data(), &len);
        hmac.resize(len);
        return hmac;
    }

    static uint16_t GetGreaseValue(uint8_t index) {
        uint8_t nibble = (index % 16) << 4 | 0x0A;
        return (nibble << 8) | nibble;
    }

    static void WriteU16(std::vector<uint8_t>& buf, uint16_t val) {
        buf.push_back(val >> 8);
        buf.push_back(val & 0xFF);
    }

    std::vector<uint8_t> TlsHelper::BuildClientHello(
        const std::string& sni,
        const std::vector<uint8_t>& clientPubKey,
        const std::vector<uint8_t>& serverPublicKey)
    {
        std::vector<uint8_t> body;

        // 1. Version: TLS 1.2 (0x0303) в Handshake Body
        WriteU16(body, 0x0303);

        // 2. Client Random (32 байта): Timestamp (4 байта) + Random Entropy (28 байт)
        std::vector<uint8_t> clientRandom(32);
        RAND_bytes(clientRandom.data(), 32);

        uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        clientRandom[0] = static_cast<uint8_t>((now >> 24) & 0xFF);
        clientRandom[1] = static_cast<uint8_t>((now >> 16) & 0xFF);
        clientRandom[2] = static_cast<uint8_t>((now >> 8) & 0xFF);
        clientRandom[3] = static_cast<uint8_t>(now & 0xFF);

        body.insert(body.end(), clientRandom.begin(), clientRandom.end());

        // 3. REALITY Session ID (32 байта) - HMAC подпись
        std::vector<uint8_t> hmacInput = clientRandom;
        hmacInput.insert(hmacInput.end(), clientPubKey.begin(), clientPubKey.end());

        auto hmac = ComputeHmacSha256(serverPublicKey, hmacInput);

        std::vector<uint8_t> sessionId(32);
        std::memcpy(sessionId.data(), hmac.data(), 16); // Метка REALITY
        RAND_bytes(sessionId.data() + 16, 16);          // Энтропия

        body.push_back(32); // Session ID Length
        body.insert(body.end(), sessionId.begin(), sessionId.end());

        // 4. Cipher Suites
        uint8_t greaseIndex = clientRandom[0];
        std::vector<uint16_t> ciphers = {
            GetGreaseValue(greaseIndex),
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
        };
        WriteU16(body, static_cast<uint16_t>(ciphers.size() * 2));
        for (uint16_t c : ciphers) WriteU16(body, c);

        // 5. Compression Methods (null compression)
        body.push_back(0x01);
        body.push_back(0x00);

        // 6. Extensions
        std::vector<uint8_t> extBuf;

        // Ext: GREASE
        WriteU16(extBuf, GetGreaseValue(greaseIndex + 1));
        WriteU16(extBuf, 0x0000);

        // Ext: SNI (0x0000)
        WriteU16(extBuf, 0x0000);
        WriteU16(extBuf, static_cast<uint16_t>(sni.size() + 5));
        WriteU16(extBuf, static_cast<uint16_t>(sni.size() + 3));
        extBuf.push_back(0x00); // Name Type: host_name
        WriteU16(extBuf, static_cast<uint16_t>(sni.size()));
        extBuf.insert(extBuf.end(), sni.begin(), sni.end());

        // Ext: extended_master_secret (0x0017)
        WriteU16(extBuf, 0x0017); WriteU16(extBuf, 0x0000);

        // Ext: renegotiation_info (0xff01)
        WriteU16(extBuf, 0xff01); WriteU16(extBuf, 0x0001); extBuf.push_back(0x00);

        // Ext: supported_groups (0x000a)
        WriteU16(extBuf, 0x000a); WriteU16(extBuf, 0x000a); WriteU16(extBuf, 0x0008);
        WriteU16(extBuf, GetGreaseValue(greaseIndex + 2));
        WriteU16(extBuf, 0x001d); // x25519
        WriteU16(extBuf, 0x0017); // secp256r1
        WriteU16(extBuf, 0x0018); // secp384r1

        // Ext: ec_point_formats (0x000b)
        WriteU16(extBuf, 0x000b); WriteU16(extBuf, 0x0002);
        extBuf.push_back(0x01); extBuf.push_back(0x00);

        // Ext: session_ticket (0x0023)
        WriteU16(extBuf, 0x0023); WriteU16(extBuf, 0x0000);

        // Ext: ALPN (0x0010)
        WriteU16(extBuf, 0x0010); WriteU16(extBuf, 14); WriteU16(extBuf, 12);
        extBuf.push_back(0x02); extBuf.push_back('h'); extBuf.push_back('2');
        extBuf.push_back(0x08);
        std::string http11 = "http/1.1";
        extBuf.insert(extBuf.end(), http11.begin(), http11.end());

        // Ext: status_request (0x0005)
        WriteU16(extBuf, 0x0005); WriteU16(extBuf, 0x0005);
        extBuf.push_back(0x01); WriteU16(extBuf, 0x0000); WriteU16(extBuf, 0x0000);

        // Ext: signature_algorithms (0x000d)
        std::vector<uint16_t> sigAlgs = { 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201 };
        WriteU16(extBuf, 0x000d); WriteU16(extBuf, static_cast<uint16_t>(sigAlgs.size() * 2 + 2));
        WriteU16(extBuf, static_cast<uint16_t>(sigAlgs.size() * 2));
        for (uint16_t sa : sigAlgs) WriteU16(extBuf, sa);

        // Ext: signed_certificate_timestamp (0x0012)
        WriteU16(extBuf, 0x0012); WriteU16(extBuf, 0x0000);

        // Ext: key_share (0x0033)
        WriteU16(extBuf, 0x0033);
        WriteU16(extBuf, 43);
        WriteU16(extBuf, 41);
        WriteU16(extBuf, GetGreaseValue(greaseIndex + 3));
        WriteU16(extBuf, 1); extBuf.push_back(0x00);
        WriteU16(extBuf, 0x001d); // x25519
        WriteU16(extBuf, 32);
        extBuf.insert(extBuf.end(), clientPubKey.begin(), clientPubKey.end());

        // Ext: psk_key_exchange_modes (0x002d)
        WriteU16(extBuf, 0x002d); WriteU16(extBuf, 0x0002);
        extBuf.push_back(0x01); extBuf.push_back(0x01);

        // Ext: supported_versions (0x002b)
        WriteU16(extBuf, 0x002b); WriteU16(extBuf, 0x0007);
        extBuf.push_back(0x06);
        WriteU16(extBuf, GetGreaseValue(greaseIndex + 4));
        WriteU16(extBuf, 0x0304); // TLS 1.3
        WriteU16(extBuf, 0x0303); // TLS 1.2

        // Ext: compress_certificate (0x001b)
        WriteU16(extBuf, 0x001b); WriteU16(extBuf, 0x0003);
        extBuf.push_back(0x02); WriteU16(extBuf, 0x0201);

        // Ext: application_settings (0x4469)
        WriteU16(extBuf, 0x4469); WriteU16(extBuf, 0x0000);

        // --- PADDING EXTENSION (0x0015) ---
        // Точный расчет: 5 (Record Hdr) + 4 (Handshake Hdr) + body.size() + 2 (Ext Length) + extBuf.size()
        size_t currentTotalLen = 5 + 4 + body.size() + 2 + extBuf.size();
        constexpr size_t TARGET_LEN = 512;

        if (currentTotalLen + 4 <= TARGET_LEN) {
            size_t padLen = TARGET_LEN - currentTotalLen - 4;
            WriteU16(extBuf, 0x0015);
            WriteU16(extBuf, static_cast<uint16_t>(padLen));
            extBuf.insert(extBuf.end(), padLen, 0x00);
        }

        // Добавляем итоговую длину расширений в body
        WriteU16(body, static_cast<uint16_t>(extBuf.size()));
        body.insert(body.end(), extBuf.begin(), extBuf.end());

        // 7. Сборка TLS Record
        std::vector<uint8_t> packet;
        packet.push_back(0x16); // Record Type: Handshake
        WriteU16(packet, 0x0301); // TLS 1.0 (для совместимости в заголовке)
        WriteU16(packet, static_cast<uint16_t>(body.size() + 4));

        packet.push_back(0x01); // Message Type: ClientHello
        packet.push_back(0x00); // 24-bit length (MSB)
        WriteU16(packet, static_cast<uint16_t>(body.size()));
        packet.insert(packet.end(), body.begin(), body.end());

        return packet;
    }

    bool TlsHelper::VerifyAndParseClientHello(
        const std::vector<uint8_t>& packet,
        const std::vector<uint8_t>& serverPublicKey,
        std::vector<uint8_t>& outClientPubKey,
        std::string& outSni)
    {
        if (packet.size() < 43) return false;

        // 1. Client Random (байты 11..42)
        std::vector<uint8_t> clientRandom(packet.begin() + 11, packet.begin() + 43);

        // 2. Session ID (начинается с байта 43)
        uint8_t sessionIdLen = packet[43];
        if (sessionIdLen != 32 || packet.size() < 44 + 32) return false;

        std::vector<uint8_t> sessionId(packet.begin() + 44, packet.begin() + 76);

        // 3. Безопасный проход по расширениям
        size_t idx = 76;
        if (idx + 2 > packet.size()) return false;

        uint16_t cipherLen = (packet[idx] << 8) | packet[idx + 1];
        idx += 2 + cipherLen;

        if (idx >= packet.size()) return false;
        uint8_t compLen = packet[idx];
        idx += 1 + compLen;

        if (idx + 2 > packet.size()) return false;
        uint16_t extLen = (packet[idx] << 8) | packet[idx + 1];
        idx += 2;

        size_t extEnd = idx + extLen;
        if (extEnd > packet.size()) return false;

        bool foundKeyShare = false;
        outSni.clear();

        while (idx + 4 <= extEnd) {
            uint16_t extType = (packet[idx] << 8) | packet[idx + 1];
            uint16_t extSize = (packet[idx + 2] << 8) | packet[idx + 3];
            idx += 4;

            if (idx + extSize > extEnd) return false;

            if (extType == 0x0000 && extSize >= 5) { // SNI
                uint16_t nameLen = (packet[idx + 3] << 8) | packet[idx + 4];
                if (idx + 5 + nameLen <= extEnd) {
                    outSni = std::string(reinterpret_cast<const char*>(&packet[idx + 5]), nameLen);
                }
            }
            else if (extType == 0x0033) { // Key Share
                size_t kIdx = idx;
                if (kIdx + 2 <= idx + extSize) {
                    uint16_t sharesLen = (packet[kIdx] << 8) | packet[kIdx + 1];
                    kIdx += 2;
                    size_t sharesEnd = kIdx + sharesLen;
                    while (kIdx + 4 <= sharesEnd && kIdx + 4 <= idx + extSize) {
                        uint16_t group = (packet[kIdx] << 8) | packet[kIdx + 1];
                        uint16_t keyLen = (packet[kIdx + 2] << 8) | packet[kIdx + 3];
                        kIdx += 4;
                        if (group == 0x001d && keyLen == 32 && kIdx + 32 <= idx + extSize) {
                            outClientPubKey.assign(packet.begin() + kIdx, packet.begin() + kIdx + 32);
                            foundKeyShare = true;
                            break;
                        }
                        kIdx += keyLen;
                    }
                }
            }
            idx += extSize;
        }

        if (!foundKeyShare || outClientPubKey.size() != 32) return false;

        // 4. Валидация HMAC подписи REALITY
        std::vector<uint8_t> hmacInput = clientRandom;
        hmacInput.insert(hmacInput.end(), outClientPubKey.begin(), outClientPubKey.end());
        auto expectedHmac = ComputeHmacSha256(serverPublicKey, hmacInput);

        if (std::memcmp(sessionId.data(), expectedHmac.data(), 16) != 0) {
            return false; // Неверный HMAC — зонд или не легитимный клиент
        }

        // 5. ПРОВЕРКА TIMESTAMP ПРОТИВ REPLAY ATTACK (Окно 60 секунд)
        uint32_t clientTimestamp = (static_cast<uint32_t>(clientRandom[0]) << 24) |
            (static_cast<uint32_t>(clientRandom[1]) << 16) |
            (static_cast<uint32_t>(clientRandom[2]) << 8) |
            static_cast<uint32_t>(clientRandom[3]);

        uint32_t currentTimestamp = static_cast<uint32_t>(std::time(nullptr));
        int64_t timeDiff = std::abs(static_cast<int64_t>(currentTimestamp) - static_cast<int64_t>(clientTimestamp));

        constexpr uint32_t TIME_WINDOW = 60; // 60 секунд окно для учета Clock Skew

        if (timeDiff > TIME_WINDOW) {
            std::cout << "[Server Fallback] Client timestamp out of bounds! Diff: " << timeDiff << "s.\n";
            return false;
        }

        // 6. ПРОВЕРКА REPLAY CACHE (Защита от повторов внутри окна в 60 сек)
        // Берем 16 байт валидированного HMAC подписи
        std::vector<uint8_t> hmacPrefix(sessionId.begin(), sessionId.begin() + 16);
        if (ReplayCache::IsReplayAndInsert(hmacPrefix, TIME_WINDOW)) {
            std::cout << "[Server Fallback] Replay Attack detected! Duplicate ClientHello within window.\n";
            return false; // Повторный пакет с тем же HMAC/SessionID -> Уходит в Fallback!
        }

        return true;
    }

    bool TlsHelper::ParseSniFromClientHello(const std::vector<uint8_t>& packet, std::string& outSni) {
        if (packet.size() < 43) return false;

        uint8_t sessionIdLen = packet[43];
        size_t idx = 44 + sessionIdLen;
        if (idx + 2 > packet.size()) return false;

        uint16_t cipherLen = (packet[idx] << 8) | packet[idx + 1];
        idx += 2 + cipherLen;

        if (idx >= packet.size()) return false;
        uint8_t compLen = packet[idx];
        idx += 1 + compLen;

        if (idx + 2 > packet.size()) return false;
        uint16_t extLen = (packet[idx] << 8) | packet[idx + 1];
        idx += 2;

        size_t extEnd = idx + extLen;
        if (extEnd > packet.size()) return false;

        while (idx + 4 <= extEnd) {
            uint16_t extType = (packet[idx] << 8) | packet[idx + 1];
            uint16_t extSize = (packet[idx + 2] << 8) | packet[idx + 3];
            idx += 4;

            if (extType == 0x0000 && extSize >= 5) {
                uint16_t nameLen = (packet[idx + 3] << 8) | packet[idx + 4];
                if (idx + 5 + nameLen <= extEnd) {
                    outSni = std::string(reinterpret_cast<const char*>(&packet[idx + 5]), nameLen);
                    return true;
                }
            }
            idx += extSize;
        }
        return false;
    }

    std::vector<uint8_t> TlsHelper::BuildServerHello(
        const std::vector<uint8_t>& serverPubKey,
        const std::vector<uint8_t>& clientSessionId)
    {
        std::vector<uint8_t> body;

        // 1. Версия TLS 1.2 (0x0303) - обязательно для совместимости
        body.push_back(0x03); body.push_back(0x03);

        // 2. Server Random (32 байта)
        std::vector<uint8_t> serverRandom(32);
        RAND_bytes(serverRandom.data(), 32);

        // По стандарту TLS 1.3, если сервер отвечает на downgrade (до TLS 1.2), 
        // он должен вставить специальный маркер в последние 8 байт Random.
        // Но так как мы согласовали TLS 1.3, оставляем просто случайные байты.
        body.insert(body.end(), serverRandom.begin(), serverRandom.end());

        // 3. Эхо Client Session ID (длина + сами байты)
        body.push_back(static_cast<uint8_t>(clientSessionId.size()));
        body.insert(body.end(), clientSessionId.begin(), clientSessionId.end());

        // 4. Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
        body.push_back(0x13); body.push_back(0x01);

        // 5. Compression: null (0x00)
        body.push_back(0x00);

        // 6. Расширения (Extensions) сервера
        std::vector<uint8_t> extBuf;

        // Ext: supported_versions (0x002b) -> подтверждаем TLS 1.3 (0x0304)
        extBuf.push_back(0x00); extBuf.push_back(0x2b); // Type
        extBuf.push_back(0x00); extBuf.push_back(0x02); // Length
        extBuf.push_back(0x03); extBuf.push_back(0x04); // Value

        // Ext: key_share (0x0033) -> наш серверный X25519 публичный ключ
        extBuf.push_back(0x00); extBuf.push_back(0x33); // Type
        extBuf.push_back(0x00); extBuf.push_back(36);   // Length
        extBuf.push_back(0x00); extBuf.push_back(0x1d); // Group: x25519
        extBuf.push_back(0x00); extBuf.push_back(32);   // Key length
        extBuf.insert(extBuf.end(), serverPubKey.begin(), serverPubKey.end());

        // Записываем длину всех расширений
        body.push_back(static_cast<uint8_t>(extBuf.size() >> 8));
        body.push_back(static_cast<uint8_t>(extBuf.size() & 0xFF));
        body.insert(body.end(), extBuf.begin(), extBuf.end());

        // --- ФОРМИРОВАНИЕ ИТОГОВОГО ПАКЕТА ---
        std::vector<uint8_t> packet;

        // [Record 1: ServerHello]
        packet.push_back(0x16); // Handshake
        packet.push_back(0x03); packet.push_back(0x03); // TLS 1.2
        uint16_t hsLen = static_cast<uint16_t>(body.size() + 4);
        packet.push_back(hsLen >> 8); packet.push_back(hsLen & 0xFF);

        packet.push_back(0x02); // Message Type: ServerHello
        packet.push_back(0x00); // Length (3 байта)
        packet.push_back(static_cast<uint8_t>(body.size() >> 8));
        packet.push_back(static_cast<uint8_t>(body.size() & 0xFF));
        packet.insert(packet.end(), body.begin(), body.end());

        // [Record 2: ChangeCipherSpec] - КРИТИЧЕСКИ ВАЖНО ДЛЯ DPI
        packet.push_back(0x14); // Тип: ChangeCipherSpec
        packet.push_back(0x03); packet.push_back(0x03); // Версия
        packet.push_back(0x00); packet.push_back(0x01); // Длина: 1 байт
        packet.push_back(0x01); // Значение (всегда 0x01)

        return packet;
    }

    bool TlsHelper::ParseServerHello(const std::vector<uint8_t>& packet, std::vector<uint8_t>& outServerPubKey) {
        if (packet.size() < 38) return false;

        uint8_t sessionIdLen = packet[43];
        size_t idx = 44 + sessionIdLen + 2 + 1; // Пропускаем SessionID, CipherSuite, Compression

        if (idx + 2 > packet.size()) return false;
        uint16_t extLen = (packet[idx] << 8) | packet[idx + 1];
        idx += 2;

        size_t extEnd = idx + extLen;
        if (extEnd > packet.size()) return false;

        while (idx + 4 <= extEnd) {
            uint16_t extType = (packet[idx] << 8) | packet[idx + 1];
            uint16_t extSize = (packet[idx + 2] << 8) | packet[idx + 3];
            idx += 4;

            if (extType == 0x0033 && extSize >= 36) { // Key Share
                uint16_t group = (packet[idx] << 8) | packet[idx + 1];
                uint16_t keyLen = (packet[idx + 2] << 8) | packet[idx + 3];
                if (group == 0x001d && keyLen == 32 && idx + 4 + 32 <= extEnd) {
                    outServerPubKey.assign(packet.begin() + idx + 4, packet.begin() + idx + 36);
                    return true;
                }
            }
            idx += extSize;
        }
        return false;
    }

} // namespace Vpn::Protocol