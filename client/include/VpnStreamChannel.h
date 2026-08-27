#pragma once
#include <memory>
#include <functional>
#include "VpnTransport.h"
#include "Protocol.h"

namespace Vpn::Client {

    class VpnStreamChannel {
    public:
        using FrameHandler = std::function<void(const Protocol::MuxFrame& frame)>;

        explicit VpnStreamChannel(std::shared_ptr<VpnTransport> transport);
        ~VpnStreamChannel();

        uint32_t GetStreamId() const { return m_streamId; }
        bool IsInteractive() const { return m_isInteractive; }

        void RegisterStream(FrameHandler handler);
        void OpenVpnStream(const Protocol::TargetAddress& target);
        void SendData(const std::vector<uint8_t>& data);
        void SendHalfClose();
        void SendCloseAndUnregister();
        bool IsTransportCongested() const {
            return m_transport ? m_transport->IsCongested() : false;
        }
    private:
        std::shared_ptr<VpnTransport> m_transport;
        uint32_t m_streamId{ 0 };
        bool m_isInteractive{ false }; // Состояние интерактивности потока
    };

} // namespace Vpn::Client