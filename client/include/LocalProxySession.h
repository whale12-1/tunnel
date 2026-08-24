#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include "SocksHandshakeHandler.h"
#include "AppSocketChannel.h"
#include "VpnStreamChannel.h"
#include "VpnTransport.h"

namespace Vpn::Client {

    using boost::asio::ip::tcp;

    class LocalProxySession : public std::enable_shared_from_this<LocalProxySession> {
    public:
        LocalProxySession(tcp::socket appSocket, std::shared_ptr<VpnTransport> transport);
        ~LocalProxySession();

        void Start();
        void Close();

    private:
        void OnMuxFrameReceived(const Protocol::MuxFrame& frame);

        std::shared_ptr<AppSocketChannel> m_appChannel;
        std::shared_ptr<SocksHandshakeHandler> m_socksHandler;
        std::shared_ptr<VpnStreamChannel> m_streamChannel;

        std::string m_sniHost;
        bool m_isTunneling{ false };
    };

} // namespace Vpn::Client