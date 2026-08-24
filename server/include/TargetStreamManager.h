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

    struct RemoteStream {
        uint32_t streamId;
        tcp::socket targetSocket;
        std::array<uint8_t, 8192> readBuffer{};
        std::deque<std::shared_ptr<std::vector<uint8_t>>> writeQueue;
        bool isWriting = false;
        bool clientFinished = false;
        bool targetFinished = false;

        explicit RemoteStream(uint32_t id, const boost::asio::any_io_executor& exec)
            : streamId(id), targetSocket(exec) {
        }
    };

    class TargetStreamManager : public std::enable_shared_from_this<TargetStreamManager> {
    public:
        using SendMuxFrameFn = std::function<void(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload)>;

        TargetStreamManager(boost::asio::any_io_executor executor, SendMuxFrameFn sendFn);

        void ProcessMuxFrame(const Protocol::MuxFrame& frame);
        void CloseAll();

    private:
        void HandleStreamOpen(uint32_t streamId, const std::vector<uint8_t>& payload);
        void HandleStreamData(uint32_t streamId, const std::vector<uint8_t>& payload);
        void HandleStreamHalfClose(uint32_t streamId);
        void HandleStreamClose(uint32_t streamId);

        void DoWriteToTarget(std::shared_ptr<RemoteStream> stream);
        void DoReadFromTarget(std::shared_ptr<RemoteStream> stream);
        void CloseStream(uint32_t streamId);

        boost::asio::any_io_executor m_executor;
        SendMuxFrameFn m_sendFn;
        std::unordered_map<uint32_t, std::shared_ptr<RemoteStream>> m_streams;
    };

} // namespace Vpn::Server