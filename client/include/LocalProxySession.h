#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <string> // Добавлено для std::string
#include "Protocol.h"
#include "VpnTransport.h"

namespace Vpn::Client {

    using boost::asio::ip::tcp;

    class LocalProxySession : public std::enable_shared_from_this<LocalProxySession> {
    public:
        explicit LocalProxySession(tcp::socket appSocket, std::shared_ptr<VpnTransport> transport);
        ~LocalProxySession();

        void Start();

    private:
        void DoReadSocksHandshake();
        void DoReadSocksRequestHeader();
        void DoReadSocksAddress(uint8_t socksAddressType);
        void SendSocksSuccessResponse();

        void OpenVpnStream(const Protocol::TargetAddress& target);
        void OnMuxFrameReceived(const Protocol::MuxFrame& frame);

        void DoReadFromApp();
        void DoWriteToApp(const uint8_t* data, size_t length);
        void DoWriteToAppQueue(); // <--- Новый метод

        void Close();

        tcp::socket m_appSocket;
        std::shared_ptr<VpnTransport> m_transport;
        uint32_t m_myStreamId;

        uint8_t m_buffer[512]{};
        std::array<uint8_t, Vpn::Protocol::MAX_PAYLOAD_SIZE> m_appBuf;
        bool m_isTunneling{ false };
        bool m_isHalfClosed = false;

        std::deque<std::shared_ptr<std::vector<uint8_t>>> m_writeQueue; // <--- Очередь
        bool m_isWriting{ false };                    // <--- Флаг
        // --- ДОБАВЛЕНО: Переменная для хранения SNI ---
        std::string m_sniHost;
    };

} // namespace Vpn::Client