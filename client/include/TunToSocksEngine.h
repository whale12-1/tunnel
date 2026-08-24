#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <utility> // Для std::pair
#include <functional>
#include <vector>
#include <cstdint>

#include "VpnTransport.h"
#include "VpnStreamChannel.h"

extern "C" {
#include "lwip/ip_addr.h"
#include "lwip/udp.h"
}

struct netif;
struct tcp_pcb;
struct pbuf;

namespace Vpn::Client {

    class Tun2SocksEngine;

    struct UdpSession {
        uint32_t streamId;
        std::shared_ptr<VpnStreamChannel> streamChannel;
        uint32_t clientIp;
        uint16_t clientPort;
        uint32_t remoteIp;
        uint16_t remotePort;
        std::chrono::steady_clock::time_point lastActive;
    };

    struct LwipTcpContext {
        Tun2SocksEngine* engine = nullptr;
        uint32_t streamId = 0;
        struct tcp_pcb* pcb = nullptr;
        std::deque<std::vector<uint8_t>> txQueue; // <-- ДОБАВЛЕНО
    };

    class Tun2SocksEngine : public std::enable_shared_from_this<Tun2SocksEngine> {
    public:
        using SendToOsCallback = std::function<void(const uint8_t* data, size_t length)>;

        Tun2SocksEngine(boost::asio::io_context& ioContext,
            std::shared_ptr<VpnTransport> transport,
            SendToOsCallback sendToOs);
        ~Tun2SocksEngine();

        void Init();

        void OnIpPacketFromOs(const uint8_t* data, size_t length);

        static signed char LwipNetifOutput(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr);
        static signed char LwipTcpAccept(void* arg, struct tcp_pcb* newpcb, signed char err);
        static signed char LwipTcpRecv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, signed char err);
        static void LwipTcpError(void* arg, signed char err);
        static void LwipUdpRecv(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port);

    private:
        void StartLwipTimer();
        std::unordered_map<uint16_t, std::pair<uint32_t, uint16_t>> m_natTable;
        void UpdateChecksums(uint8_t* packet, size_t len, uint16_t ip_header_len);
        void TrySendTcpData(LwipTcpContext* ctx);
        std::string IpToString(uint32_t ip);

        static signed char LwipTcpSent(void* arg, struct tcp_pcb* tpcb, u16_t len);
        boost::asio::io_context& m_ioContext;
        boost::asio::steady_timer m_lwipTimer;
        std::shared_ptr<VpnTransport> m_transport;
        SendToOsCallback m_sendToOs;

        std::unique_ptr<struct netif> m_netif;
        std::mutex m_engineMutex;
        std::unordered_map<uint32_t, std::shared_ptr<VpnStreamChannel>> m_streams;
        std::unordered_map<uint32_t, std::unique_ptr<LwipTcpContext>> m_tcpContexts;

        std::unordered_map<uint16_t, std::shared_ptr<UdpSession>> m_udpSessions;

        void OnServerUdpData(uint16_t clientPort, const Protocol::MuxFrame& frame);
        void RemoveUdpSession(uint16_t clientPort);
        void CheckUdpTimeouts();

        struct udp_pcb* m_udpPcb = nullptr;

        void OnServerTcpData(uint32_t streamId, const Protocol::MuxFrame& frame);
        void RemoveTcpConnection(uint32_t streamId);

        static signed char LwipNetifInit(struct netif* netif);
    };

} // namespace Vpn::Client