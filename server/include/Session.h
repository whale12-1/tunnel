#pragma once
#include <boost/asio.hpp>
#include <memory>
#include "CryptoEngine.h"
#include "TlsHandshakeHandler.h"
#include "FallbackRelay.h"
#include "MuxConnection.h"
#include "TargetStreamManager.h"

namespace Vpn::Server {

    using boost::asio::ip::tcp;

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(tcp::socket clientSocket, std::shared_ptr<CryptoEngine> cryptoEngine);

        void Start();

    private:
        void OnHandshakeSuccess(tcp::socket socket, std::vector<uint8_t> sessionKey);
        void OnFallback(tcp::socket socket, std::shared_ptr<std::vector<uint8_t>> initialPacket);
        void OnConnectionError();

        tcp::socket m_initialSocket;
        std::shared_ptr<CryptoEngine> m_cryptoEngine;

        // Рабочие слои
        std::shared_ptr<TlsHandshakeHandler> m_handshakeHandler;
        std::shared_ptr<FallbackRelay> m_fallbackRelay;
        std::shared_ptr<MuxConnection> m_muxConnection;
        std::shared_ptr<TargetStreamManager> m_targetManager;
    };

} // namespace Vpn::Server