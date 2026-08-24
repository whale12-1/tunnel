#include "Session.h"
#include <iostream>

namespace Vpn::Server {

    Session::Session(tcp::socket clientSocket, std::shared_ptr<CryptoEngine> cryptoEngine)
        : m_initialSocket(std::move(clientSocket)),
        m_cryptoEngine(std::move(cryptoEngine)) {
    }

    void Session::Start() {
        m_handshakeHandler = std::make_shared<TlsHandshakeHandler>(m_cryptoEngine, m_initialSocket.get_executor());

        auto self = shared_from_this();
        m_handshakeHandler->Start(
            std::move(m_initialSocket),
            [this, self](tcp::socket socket, std::vector<uint8_t> sessionKey) {
                OnHandshakeSuccess(std::move(socket), std::move(sessionKey));
            },
            [this, self](tcp::socket socket, std::shared_ptr<std::vector<uint8_t>> initialPacket) {
                OnFallback(std::move(socket), std::move(initialPacket));
            }
        );
    }

    void Session::OnHandshakeSuccess(tcp::socket socket, std::vector<uint8_t> sessionKey) {
        // Инициализируем транспорт Mux
        m_muxConnection = std::make_shared<MuxConnection>(std::move(socket), std::move(sessionKey), m_cryptoEngine);

        // Инициализируем маршрутизатор потоков
        m_targetManager = std::make_shared<TargetStreamManager>(
            m_muxConnection->GetSocketExecutor(), // Вспомогательный метод (нужно добавить геттер в Mux, либо использовать asio::system_executor)
            [weakMux = std::weak_ptr<MuxConnection>(m_muxConnection)](uint32_t id, Protocol::Command cmd, const std::vector<uint8_t>& payload) {
                if (auto mux = weakMux.lock()) {
                    mux->SendMuxFrame(id, cmd, payload);
                }
            }
        );

        auto self = shared_from_this();
        m_muxConnection->Start(
            [this, self](const Protocol::MuxFrame& frame) {
                m_targetManager->ProcessMuxFrame(frame);
            },
            [this, self]() {
                OnConnectionError();
            }
        );
    }

    void Session::OnFallback(tcp::socket socket, std::shared_ptr<std::vector<uint8_t>> initialPacket) {
        m_fallbackRelay = std::make_shared<FallbackRelay>(std::move(socket));
        m_fallbackRelay->Start(std::move(initialPacket));
    }

    void Session::OnConnectionError() {
        if (m_targetManager) {
            m_targetManager->CloseAll();
        }
    }

} // namespace Vpn::Server