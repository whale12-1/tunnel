#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <functional>
#include "CryptoEngine.h"
#include "Protocol.h"

namespace Vpn::Server {

    using boost::asio::ip::tcp;

    class TlsHandshakeHandler : public std::enable_shared_from_this<TlsHandshakeHandler> {
    public:
        using SuccessCallback = std::function<void(tcp::socket socket, std::vector<uint8_t> sessionKey)>;
        using FallbackCallback = std::function<void(tcp::socket socket, std::shared_ptr<std::vector<uint8_t>> initialPacket)>;

        TlsHandshakeHandler(std::shared_ptr<CryptoEngine> cryptoEngine, boost::asio::any_io_executor executor);

        void Start(tcp::socket socket, SuccessCallback onSuccess, FallbackCallback onFallback);

    private:
        void DoReadHandshake();
        void DoReadTlsBody(uint16_t bodyLen);
        void FinishWithFallback(std::shared_ptr<std::vector<uint8_t>> initialPacket);

        tcp::socket m_socket;
        std::shared_ptr<CryptoEngine> m_cryptoEngine;
        std::vector<uint8_t> m_payloadBuffer;

        SuccessCallback m_onSuccess;
        FallbackCallback m_onFallback;
    };

} // namespace Vpn::Server