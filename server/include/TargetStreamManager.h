#pragma once
#include <boost/asio.hpp>
#include <unordered_map>
#include <memory>
#include <deque>
#include <vector>
#include <functional>
#include "Protocol.h"

namespace Vpn::Server {

    using boost::asio::ip::tcp;
    using boost::asio::ip::udp;

    struct RemoteStream {
        uint32_t streamId;
        bool isUdp = false;
        bool isInteractive = false; // Флаг приоритета для интерактивного трафика (SSH, DNS и т.д.)
        bool isConnected = false;

        tcp::socket targetSocket;
        udp::socket udpSocket;

        udp::endpoint remoteUdpEndpoint;

        // Таймер простоя ИСПОЛЬЗУЕТСЯ ТОЛЬКО ДЛЯ UDP
        boost::asio::steady_timer udpIdleTimer;

        std::deque<std::shared_ptr<std::vector<uint8_t>>> writeQueue;
        bool isWriting = false;
        std::vector<uint8_t> readBuffer;
        bool targetFinished = false;
        bool clientFinished = false;

        RemoteStream(uint32_t id, boost::asio::any_io_executor ex)
            : streamId(id),
            targetSocket(ex),
            udpSocket(ex),
            udpIdleTimer(ex) {
            readBuffer.resize(65535);
        }
    };

    class TargetStreamManager : public std::enable_shared_from_this<TargetStreamManager> {
    public:
        // Передаем bool isInteractive в callback отправки
        using SendMuxFrameFn = std::function<void(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload, bool isInteractive)>;

        TargetStreamManager(boost::asio::any_io_executor executor, SendMuxFrameFn sendFn);

        void ProcessMuxFrame(const Protocol::MuxFrame& frame);
        void CloseAll();

    private:
        void HandleStreamOpen(uint32_t streamId, const std::vector<uint8_t>& payload);
        void HandleStreamData(uint32_t streamId, const std::vector<uint8_t>& payload);
        void HandleStreamHalfClose(uint32_t streamId);
        void HandleStreamClose(uint32_t streamId);

        void DoWriteToUdpTarget(std::shared_ptr<RemoteStream> stream);
        void DoReadFromUdpTarget(std::shared_ptr<RemoteStream> stream);
        void DoWriteToTarget(std::shared_ptr<RemoteStream> stream);
        void DoReadFromTarget(std::shared_ptr<RemoteStream> stream);

        void RefreshUdpTimeout(std::shared_ptr<RemoteStream> stream);
        void CloseStream(uint32_t streamId, bool notifyRemote = true);

        boost::asio::any_io_executor m_executor;
        SendMuxFrameFn m_sendFn;
        std::unordered_map<uint32_t, std::shared_ptr<RemoteStream>> m_streams;
    };

} // namespace Vpn::Server