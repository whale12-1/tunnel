#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <random>

namespace Vpn::Protocol {

    constexpr size_t MAX_FRAME_SIZE = 16384; // 16 KB (максимальный размер TLS-записи)
    constexpr size_t MAX_PAYLOAD_SIZE = 15000;
    constexpr size_t TAG_SIZE = 16;
    constexpr size_t IV_SIZE = 12;

    // Системный StreamID для служебных кадров (Ping/Pong/Auth)
    constexpr uint32_t SYSTEM_STREAM_ID = 0;

    enum class Command : uint8_t {
        Ping = 0x01, // Системный Heartbeat
        Pong = 0x02, // Ответ на Heartbeat
        StreamOpen = 0x03, // Запрос на открытие виртуального канала к TargetAddress
        StreamData = 0x04, // Передача полезных данных в рамках StreamID
        StreamHalfClose = 0x05,
        StreamClose = 0x06  // Закрытие конкретного StreamID
    };

    enum class AddressType : uint8_t {
        IPv4 = 0x01,
        Domain = 0x02,
        IPv6 = 0x03
    };

    struct TargetAddress {
        AddressType type{ AddressType::IPv4 };
        std::string address;
        uint16_t port{ 0 };
        bool isUdp{ false };
    };

    // Распакованная структура Mux-кадра
    struct MuxFrame {
        uint32_t streamId{ SYSTEM_STREAM_ID };
        Command command{ Command::Ping };
        std::vector<uint8_t> payload;
    };

    class StreamFrameHelper {
    public:
        // --- 1. MUX УПАКОВКА И РАСПАКОВКА ---
        // Собирает буфер: [StreamID (4B)][Command (1B)][Payload]
        static std::vector<uint8_t> PackMuxFrame(uint32_t streamId, Command cmd, const std::vector<uint8_t>& payload = {});

        // Разбирает незашифрованный буфер в структуру MuxFrame
        static bool UnpackMuxFrame(const std::vector<uint8_t>& plainText, MuxFrame& outFrame);

        // --- 2. СЕРИАЛИЗАЦИЯ И ПАРСИНГ АДРЕСОВ НАЗНАЧЕНИЯ ---
        static std::vector<uint8_t> SerializeTargetAddress(const TargetAddress& target);
        static bool DeserializeTargetAddress(const uint8_t* buffer, size_t size, TargetAddress& outTarget);

        // --- 3. TCP FRAMING (Заголовок длины кадра в сети) ---
        static std::vector<uint8_t> PackTcpFrame(const std::vector<uint8_t>& encryptedData);
        static std::optional<uint16_t> ReadFrameHeader(const uint8_t* buffer, size_t availableBytes);
    };

    class PaddingHelper {
    public:
        // Упаковывает полезные данные со случайным падингом (от 0 до maxPadding байт)
        static std::vector<uint8_t> AddPadding(const std::vector<uint8_t>& plainText, uint8_t maxPadding = 64) {
            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<uint16_t> dist(0, maxPadding);
            uint8_t padLen = static_cast<uint8_t>(dist(rng));

            std::vector<uint8_t> paddedData;
            paddedData.reserve(1 + plainText.size() + padLen);

            // 1. Первый байт — длина падинга
            paddedData.push_back(padLen);

            // 2. Полезные данные
            paddedData.insert(paddedData.end(), plainText.begin(), plainText.end());

            // 3. Случайные байты падинга
            for (uint8_t i = 0; i < padLen; ++i) {
                paddedData.push_back(static_cast<uint8_t>(dist(rng) & 0xFF));
            }

            return paddedData;
        }

        // Извлекает полезные данные, отбрасывая падинг
        static bool RemovePadding(const std::vector<uint8_t>& paddedData, std::vector<uint8_t>& outPlainText) {
            if (paddedData.empty()) return false;

            uint8_t padLen = paddedData[0];

            // ЗАЩИТА: Если размер кадра меньше или равен 1 + padLen, значит кадр поврежден
            if (paddedData.size() <= static_cast<size_t>(1 + padLen)) {
                return false;
            }

            size_t plainTextLen = paddedData.size() - 1 - padLen;
            outPlainText.assign(paddedData.begin() + 1, paddedData.begin() + 1 + plainTextLen);
            return true;
        }
    };

} // namespace Vpn::Protocol