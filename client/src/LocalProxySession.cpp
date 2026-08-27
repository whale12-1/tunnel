#include "LocalProxySession.h"
#include <iostream>

namespace Vpn::Client {

    LocalProxySession::LocalProxySession(tcp::socket appSocket, std::shared_ptr<VpnTransport> transport)
        : m_appChannel(std::make_shared<AppSocketChannel>(std::move(appSocket))),
        m_socksHandler(std::make_shared<SocksHandshakeHandler>(m_appChannel->GetSocket())),
        m_streamChannel(std::make_shared<VpnStreamChannel>(std::move(transport))) {
    }

    LocalProxySession::~LocalProxySession() {
        Close();
    }

    void LocalProxySession::Start() {
        auto self = shared_from_this();

        m_streamChannel->RegisterStream([this, self](const Protocol::MuxFrame& frame) {
            OnMuxFrameReceived(frame);
            });

        m_socksHandler->Start(
            [this, self](const Protocol::TargetAddress& target) {
                // --- НАЧАЛО ИЗМЕНЕНИЙ ---
                // Создаем копию, так как исходный target передается по константной ссылке
                Protocol::TargetAddress mutableTarget = target;

                if (mutableTarget.type == Protocol::AddressType::Domain) {
                    m_sniHost = mutableTarget.address;
                }

                // Простая эвристика для SOCKS (SSH, DNS, RDP)
                if (mutableTarget.port == 22 || mutableTarget.port == 53 || mutableTarget.port == 3389) {
                    mutableTarget.isInteractive = true;
                }

                m_streamChannel->OpenVpnStream(mutableTarget);
                // --- КОНЕЦ ИЗМЕНЕНИЙ ---
            },
            [this, self]() {
                Close();
            }
        );
    }

    void LocalProxySession::OnMuxFrameReceived(const Protocol::MuxFrame& frame) {
        auto self = shared_from_this();

        if (frame.command == Protocol::Command::StreamOpen) {
            std::cout << "[Client Proxy] Stream #" << m_streamChannel->GetStreamId() << " opened successfully by server.\n";

            m_socksHandler->SendSuccessResponse(
                [this, self]() {
                    m_isTunneling = true;
                    std::cout << "[Client Proxy] SOCKS tunneling active for stream #" << m_streamChannel->GetStreamId() << "\n";

                    m_appChannel->StartReading(
                        m_streamChannel->GetStreamId(),
                        [this, self](const std::vector<uint8_t>& data) {
                            m_streamChannel->SendData(data);
                        },
                        [this, self]() {
                            m_streamChannel->SendHalfClose();
                        },
                        [this, self]() {
                            Close();
                        },
                        [this, self]() { 
                            return m_streamChannel->IsTransportCongested(); 
                        }

                    );
                },
                [this, self]() {
                    Close();
                }
            );
        }
        else if (frame.command == Protocol::Command::StreamData) {
            m_appChannel->Write(m_streamChannel->GetStreamId(), frame.payload.data(), frame.payload.size(), [this, self]() {
                Close();
                });
        }
        else if (frame.command == Protocol::Command::StreamHalfClose) {
            std::cout << "[Client Proxy] Half-close received from server for stream #" << m_streamChannel->GetStreamId() << "\n";
            m_appChannel->ShutdownSend();
        }
        else if (frame.command == Protocol::Command::StreamClose) {
            std::cout << "[Client Proxy] Stream #" << m_streamChannel->GetStreamId() << " closed by server.\n";
            Close();
        }
    }

    void LocalProxySession::Close() {
        if (m_streamChannel) {
            m_streamChannel->SendCloseAndUnregister();
        }
        if (m_appChannel) {
            m_appChannel->Close();
        }
    }

} // namespace Vpn::Client