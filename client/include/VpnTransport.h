#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <unordered_map>
#include <deque>
#include <functional>
#include <atomic>
#include <mutex>

#include "Protocol.h"
#include "CryptoEngine.h"

namespace Vpn::Client {

    using boost::asio::ip::tcp;

    class VpnTransport : public std::enable_shared_from_this<VpnTransport> {
    public:
        using FrameHandler = std::function<void(const Protocol::MuxFrame&)>;

        explicit VpnTransport(boost::asio::io_context& ioContext,
            std::string serverIp,
            uint16_t serverPort,
            std::vector<uint8_t> serverPublicKey);

        // Управление подключением к VPN
        void Connect(std::function<void(bool success)> onConnected);
        bool IsConnected() const { return m_isConnected; }

        // Регистрация каналов
        uint32_t AllocateStreamId();
        void RegisterStream(uint32_t streamId, FrameHandler handler);
        void UnregisterStream(uint32_t streamId);

        // Отправка кадра в единую магистраль
        void SendMuxFrame(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload = {});

        void Close();

    private:

        void DoReadFrameHeader();
        void DoReadFramePayload(uint16_t payloadLen);
        void ProcessMuxFrame(const std::vector<uint8_t>& encryptedData);
        void DoWriteQueue();

        void StartPingTimer();

        boost::asio::io_context& m_ioContext;
        tcp::socket m_vpnSocket;
        std::string m_serverIp;
        uint16_t m_serverPort;

        bool m_isConnected{ false };
        CryptoEngine m_cryptoEngine;
        std::vector<uint8_t> m_sessionKey;

        // Диспетчер активных стримов
        std::atomic<uint32_t> m_nextStreamId{ 1 };
        std::recursive_mutex m_handlersMutex;
        std::unordered_map<uint32_t, FrameHandler> m_streamHandlers;

        // Очередь записи в единственный TCP сокет
        std::deque<std::shared_ptr<std::vector<uint8_t>>> m_writeQueue;
        bool m_isWriting{ false };

        uint8_t m_lengthBuffer[2]{};
        std::vector<uint8_t> m_payloadBuffer;

        boost::asio::steady_timer m_pingTimer;
        std::vector<uint8_t> m_serverPublicKey;

        boost::asio::steady_timer m_reconnectTimer;
        bool m_shouldAutoReconnect{ true };
        bool m_isReconnecting{ false };
        int m_reconnectAttempt{ 0 };

        void ScheduleReconnect();
    };

} // namespace Vpn::Client