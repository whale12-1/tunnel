#include "VpnStreamChannel.h"
#include <iostream>

namespace Vpn::Client {

    VpnStreamChannel::VpnStreamChannel(std::shared_ptr<VpnTransport> transport)
        : m_transport(std::move(transport)),
        m_streamId(m_transport ? m_transport->AllocateStreamId() : 0) {
    }

    VpnStreamChannel::~VpnStreamChannel() {
        SendCloseAndUnregister();
    }

    void VpnStreamChannel::RegisterStream(FrameHandler handler) {
        if (m_transport && m_streamId != 0) {
            m_transport->RegisterStream(m_streamId, std::move(handler));
        }
    }

    void VpnStreamChannel::OpenVpnStream(const Protocol::TargetAddress& target) {
        // Сохраняем флаг интерактивности для текущего потока
        m_isInteractive = target.isInteractive;

        std::cout << "[Client Proxy] Opening VPN stream #" << m_streamId
            << " for " << target.address << ":" << target.port
            << " (Interactive: " << (m_isInteractive ? "true" : "false") << ")\n";

        auto targetPayload = Protocol::StreamFrameHelper::SerializeTargetAddress(target);
        if (m_transport) {
            m_transport->SendMuxFrame(m_streamId, Protocol::Command::StreamOpen, targetPayload, m_isInteractive);
        }
    }

    void VpnStreamChannel::SendData(const std::vector<uint8_t>& data) {
        if (m_transport && m_streamId != 0) {
            m_transport->SendMuxFrame(m_streamId, Protocol::Command::StreamData, data, m_isInteractive);
        }
    }

    void VpnStreamChannel::SendHalfClose() {
        if (m_transport && m_streamId != 0) {
            m_transport->SendMuxFrame(m_streamId, Protocol::Command::StreamHalfClose, {}, m_isInteractive);
        }
    }

    void VpnStreamChannel::SendCloseAndUnregister() {
        if (m_streamId != 0 && m_transport) {
            std::cout << "[Client Proxy] Closing session for stream #" << m_streamId << "\n";
            m_transport->SendMuxFrame(m_streamId, Protocol::Command::StreamClose, {}, m_isInteractive);
            m_transport->UnregisterStream(m_streamId);
            m_streamId = 0;
        }
    }

} // namespace Vpn::Client