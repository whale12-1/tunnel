#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <deque>
#include <functional>
#include "CryptoEngine.h"
#include "Protocol.h"

namespace Vpn::Server {

    using boost::asio::ip::tcp;

    class MuxConnection : public std::enable_shared_from_this<MuxConnection> {
    public:
        using FrameHandler = std::function<void(const Protocol::MuxFrame& frame)>;
        using ErrorHandler = std::function<void()>;

        MuxConnection(tcp::socket socket, std::vector<uint8_t> sessionKey, std::shared_ptr<CryptoEngine> cryptoEngine);

        boost::asio::any_io_executor GetSocketExecutor() {
            return m_socket.get_executor();
        }
        void Start(FrameHandler onFrame, ErrorHandler onError);
        void SendMuxFrame(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload, bool isInteractive);
        void Close();

    private:
        void DoReadFrameHeader();
        void DoReadFramePayload(uint16_t payloadLen);
        void ProcessMuxFrame(const std::vector<uint8_t>& encryptedData);
        void DoWriteQueue();
        void SendTlsAlertAndClose(uint8_t alertDescription);

        tcp::socket m_socket;
        std::vector<uint8_t> m_sessionKey;
        std::shared_ptr<CryptoEngine> m_cryptoEngine;

        std::vector<uint8_t> m_payloadBuffer;
        std::deque<std::shared_ptr<std::vector<uint8_t>>> m_writeQueue;
        bool m_isWriting{ false };

        FrameHandler m_onFrame;
        ErrorHandler m_onError;
    };

} // namespace Vpn::Server