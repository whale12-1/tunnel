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

        void RegisterStream(FrameHandler handler);
        void OpenVpnStream(const Protocol::TargetAddress& target);
        void SendData(const std::vector<uint8_t>& data);
        void SendHalfClose();
        void SendCloseAndUnregister();

    private:
        std::shared_ptr<VpnTransport> m_transport;
        uint32_t m_streamId{ 0 };
    };

} // namespace Vpn::Client