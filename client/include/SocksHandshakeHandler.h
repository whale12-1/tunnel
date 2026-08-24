#pragma once
#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include "Protocol.h"

namespace Vpn::Client {

    using boost::asio::ip::tcp;

    class SocksHandshakeHandler : public std::enable_shared_from_this<SocksHandshakeHandler> {
    public:
        using TargetAddressCallback = std::function<void(const Protocol::TargetAddress& target)>;
        using ErrorCallback = std::function<void()>;
        using SuccessCallback = std::function<void()>;

        explicit SocksHandshakeHandler(tcp::socket& appSocket);

        void Start(TargetAddressCallback onTargetResolved, ErrorCallback onError);
        void SendSuccessResponse(SuccessCallback onSent, ErrorCallback onError);

    private:
        void DoReadSocksHandshake();
        void DoReadSocksRequestHeader();
        void DoReadSocksAddress(uint8_t socksAddressType);

        tcp::socket& m_appSocket;
        uint8_t m_buffer[256]{};

        TargetAddressCallback m_onTargetResolved;
        ErrorCallback m_onError;
    };

} // namespace Vpn::Client