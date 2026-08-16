#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <unordered_map>
#include <deque>
#include <array>
#include "CryptoEngine.h"
#include "Protocol.h"

namespace Vpn::Server {

    using boost::asio::ip::tcp;

    // Структура отдельного виртуального стрима (соединения с целевым сайтом)
    struct RemoteStream {
        uint32_t streamId;
        tcp::socket targetSocket;
        std::deque<std::shared_ptr<std::vector<uint8_t>>> writeQueue;
        std::array<uint8_t, 8192> readBuffer;
        bool isWriting = false;
        bool clientFinished = false;
        bool targetFinished = false;

        // Универсальный конструктор executor'а Boost.Asio
        RemoteStream(uint32_t id, const boost::asio::any_io_executor& exec)
            : streamId(id), targetSocket(exec) {
        }
    };

    class Session : public std::enable_shared_from_this<Session> {
    public:
        explicit Session(tcp::socket clientSocket, std::shared_ptr<CryptoEngine> cryptoEngine);
        void Start();

    private:
        enum class State {
            Handshake,
            Tunneling
        };

        // --- Рукопожатие и TLS Fallback ---
        void DoReadHandshake();
        void DoReadTlsBody(uint16_t bodyLen);
        void DoFallbackToRealServer(std::shared_ptr<std::vector<uint8_t>> initialPacket);
        void StartRawRelaying();
        void RelayClientToFallback();
        void RelayFallbackToClient();

        // Буферы для сквозного моста (Fallback)
        std::array<uint8_t, 8192> m_c2fBuffer; // Client -> Fallback
        std::array<uint8_t, 8192> m_f2cBuffer; // Fallback -> Client

        // --- Главный Mux-петлевой циркулятор ---
        void DoReadFrameHeader();
        void DoReadFramePayload(uint16_t payloadLen);
        void ProcessMuxFrame(const std::vector<uint8_t>& encryptedData);

        // --- Обработчики Mux-команд ---
        void HandleStreamOpen(uint32_t streamId, const std::vector<uint8_t>& payload);
        void HandleStreamData(uint32_t streamId, const std::vector<uint8_t>& payload);
        void DoWriteToTarget(std::shared_ptr<RemoteStream> stream);
        void HandleStreamClose(uint32_t streamId);
        void HandleStreamHalfClose(uint32_t streamId);

        // --- Чтение данных от целевых сайтов и отправка в туннель ---
        void DoReadFromTarget(std::shared_ptr<RemoteStream> stream);
        void CloseStream(uint32_t streamId);
        void SendTlsAlertAndClose(uint8_t alertDescription);

        // --- Потокобезопасная очередь отправки клиенту ---
        void SendMuxFrame(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload = {});
        void DoWriteQueue();

        tcp::socket m_clientSocket;
        tcp::socket m_fallbackSocket; // Для Fallback режима
        std::shared_ptr<CryptoEngine> m_cryptoEngine;
        std::vector<uint8_t> m_sessionKey;

        State m_state{ State::Handshake };
        std::vector<uint8_t> m_payloadBuffer;

        // Таблица активных виртуальных каналов
        std::unordered_map<uint32_t, std::shared_ptr<RemoteStream>> m_streams;

        // Очередь асинхронной записи в физический сокет с защитой через shared_ptr
        std::deque<std::shared_ptr<std::vector<uint8_t>>> m_writeQueue;
        bool m_isWriting{ false };

        void CloseAll();
    };

} // namespace Vpn::Server