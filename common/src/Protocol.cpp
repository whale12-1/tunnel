#include "Protocol.h"
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace Vpn::Protocol {

    // -------------------------------------------------------------------
    // 1. MUX Сериализация и Десериализация
    // -------------------------------------------------------------------
    std::vector<uint8_t> StreamFrameHelper::PackMuxFrame(uint32_t streamId, Command cmd, const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> buffer;
        buffer.reserve(5 + payload.size());

        // Запись StreamID в сетевом формате Big-Endian (4 байта)
        uint32_t netStreamId = htonl(streamId);
        const uint8_t* streamBytes = reinterpret_cast<const uint8_t*>(&netStreamId);
        buffer.insert(buffer.end(), streamBytes, streamBytes + 4);

        // Запись Команды (1 байт)
        buffer.push_back(static_cast<uint8_t>(cmd));

        // Полезная нагрузка
        if (!payload.empty()) {
            buffer.insert(buffer.end(), payload.begin(), payload.end());
        }

        return buffer;
    }

    bool StreamFrameHelper::UnpackMuxFrame(const std::vector<uint8_t>& plainText, MuxFrame& outFrame) {
        // Минимальный размер Mux-кадра: StreamID(4B) + Command(1B) = 5B
        if (plainText.size() < 5) return false;

        // Чтение StreamID
        uint32_t netStreamId = 0;
        std::memcpy(&netStreamId, plainText.data(), 4);
        outFrame.streamId = ntohl(netStreamId);

        // Чтение Command
        outFrame.command = static_cast<Command>(plainText[4]);

        // Извлечение Payload (если есть)
        if (plainText.size() > 5) {
            outFrame.payload.assign(plainText.begin() + 5, plainText.end());
        }
        else {
            outFrame.payload.clear();
        }

        return true;
    }

    // -------------------------------------------------------------------
    // 2. Сериализация и Парсинг адресов назначения (TargetAddress)
    // -------------------------------------------------------------------
    std::vector<uint8_t> StreamFrameHelper::SerializeTargetAddress(const TargetAddress& target) {
        std::vector<uint8_t> buffer;

        buffer.push_back(static_cast<uint8_t>(target.type));

        // Битовые флаги: Bit 0 — isUdp, Bit 1 — isInteractive
        uint8_t flags = 0;
        if (target.isUdp)         flags |= 0x01;
        if (target.isInteractive) flags |= 0x02;
        buffer.push_back(flags);

        if (target.type == AddressType::IPv4) {
            in_addr addr{};
            if (inet_pton(AF_INET, target.address.c_str(), &addr) == 1) {
                const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr.s_addr);
                buffer.insert(buffer.end(), bytes, bytes + 4);
            }
            else {
                return {};
            }
        }
        else if (target.type == AddressType::Domain) {
            if (target.address.size() > 255) return {};
            buffer.push_back(static_cast<uint8_t>(target.address.size()));
            buffer.insert(buffer.end(), target.address.begin(), target.address.end());
        }
        else if (target.type == AddressType::IPv6) {
            in6_addr addr6{};
            if (inet_pton(AF_INET6, target.address.c_str(), &addr6) == 1) {
                const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr6.s6_addr);
                buffer.insert(buffer.end(), bytes, bytes + 16);
            }
            else {
                return {};
            }
        }

        // Запись порта в Big-Endian (2 байта)
        uint16_t netPort = htons(target.port);
        const uint8_t* portBytes = reinterpret_cast<const uint8_t*>(&netPort);
        buffer.insert(buffer.end(), portBytes, portBytes + 2);

        return buffer;
    }

    bool StreamFrameHelper::DeserializeTargetAddress(const uint8_t* buffer, size_t size, TargetAddress& outTarget) {
        if (!buffer || size < 4) return false; // Минимально: AddrType(1B) + Flags(1B) + Port(2B) = 4B

        size_t offset = 0;
        outTarget.type = static_cast<AddressType>(buffer[offset++]);

        // Чтение битовых флагов
        uint8_t flags = buffer[offset++];
        outTarget.isUdp = (flags & 0x01) != 0;
        outTarget.isInteractive = (flags & 0x02) != 0;

        if (outTarget.type == AddressType::IPv4) {
            if (size < offset + 4 + 2) return false;

            char ipStr[INET_ADDRSTRLEN];
            in_addr addr{};
            std::memcpy(&addr.s_addr, buffer + offset, 4);
            offset += 4;

            if (inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr))) {
                outTarget.address = ipStr;
            }
            else {
                return false;
            }
        }
        else if (outTarget.type == AddressType::Domain) {
            if (size < offset + 1) return false;

            uint8_t domainLen = buffer[offset++];
            if (size < offset + domainLen + 2) return false;

            outTarget.address = std::string(reinterpret_cast<const char*>(buffer + offset), domainLen);
            offset += domainLen;
        }
        else if (outTarget.type == AddressType::IPv6) {
            if (size < offset + 16 + 2) return false;

            char ipStr[INET6_ADDRSTRLEN];
            in6_addr addr6{};
            std::memcpy(&addr6.s6_addr, buffer + offset, 16);
            offset += 16;

            if (inet_ntop(AF_INET6, &addr6, ipStr, sizeof(ipStr))) {
                outTarget.address = ipStr;
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }

        uint16_t netPort = 0;
        std::memcpy(&netPort, buffer + offset, 2);
        outTarget.port = ntohs(netPort);

        return true;
    }

    // -------------------------------------------------------------------
    // 3. Формирование и парсинг TCP-кадра сети (2-байтовый заголовок длины)
    // -------------------------------------------------------------------
    std::vector<uint8_t> StreamFrameHelper::PackTcpFrame(const std::vector<uint8_t>& encryptedData) {
        if (encryptedData.empty() || encryptedData.size() > MAX_FRAME_SIZE) {
            return {};
        }

        std::vector<uint8_t> frame;
        frame.reserve(2 + encryptedData.size());

        uint16_t length = htons(static_cast<uint16_t>(encryptedData.size()));
        const uint8_t* lenBytes = reinterpret_cast<const uint8_t*>(&length);

        frame.insert(frame.end(), lenBytes, lenBytes + 2);
        frame.insert(frame.end(), encryptedData.begin(), encryptedData.end());

        return frame;
    }

    std::optional<uint16_t> StreamFrameHelper::ReadFrameHeader(const uint8_t* buffer, size_t availableBytes) {
        if (availableBytes < 2) {
            return std::nullopt;
        }

        uint16_t netLength = 0;
        std::memcpy(&netLength, buffer, 2);
        return ntohs(netLength);
    }

} // namespace Vpn::Protocol