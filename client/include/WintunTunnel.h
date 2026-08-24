#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <boost/asio.hpp>
#include <boost/asio/windows/object_handle.hpp>
#include <memory>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <string>

#include "VpnTransport.h"
#include "VpnStreamChannel.h"
#include "TunToSocksEngine.h"

// Объявление типов вызовов библиотеки Wintun
typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

namespace Vpn::Client {

    class WintunTunnel : public std::enable_shared_from_this<WintunTunnel> {
    public:
        void SetupRouting(const std::string& serverIp);
        void ClearRouting();

        WintunTunnel(boost::asio::io_context& ioContext, std::shared_ptr<VpnTransport> transport);
        ~WintunTunnel();

        bool InitAdapter(const std::wstring& adapterName = L"CustomVPN");
        void Start();
        void Stop();

        // Запись пакета обратно в ОС (в сетевой стек Windows)
        void SendPacketToOs(const uint8_t* data, size_t length);

    private:
        void DoAsyncRead();
        void ProcessIpPacket(const uint8_t* packetData, size_t length);
        bool LoadWintunFunctions();

        boost::asio::io_context& m_ioContext;
        std::shared_ptr<VpnTransport> m_transport;

        // Поля для работы с нативным IP Helper API
        NET_LUID m_luid{};
        std::string m_serverIp;

        HMODULE m_wintunDll{ nullptr };
        WINTUN_ADAPTER_HANDLE m_adapter{ nullptr };
        WINTUN_SESSION_HANDLE m_session{ nullptr };

        std::unique_ptr<boost::asio::windows::object_handle> m_readWaitEvent;
        std::shared_ptr<Tun2SocksEngine> m_engine;

        // Структура ключа для TCP-сессий
        struct FlowKey {
            uint32_t srcIp;
            uint32_t dstIp;
            uint16_t srcPort;
            uint16_t dstPort;

            bool operator==(const FlowKey& other) const {
                return srcIp == other.srcIp && dstIp == other.dstIp &&
                    srcPort == other.srcPort && dstPort == other.dstPort;
            }
        };

        struct FlowKeyHash {
            size_t operator()(const FlowKey& k) const {
                return k.srcIp ^ k.dstIp ^ (k.srcPort << 16) ^ k.dstPort;
            }
        };

        std::atomic<bool> m_isStopping{ false };
        std::mutex m_streamsMutex;
        std::unordered_map<FlowKey, std::shared_ptr<VpnStreamChannel>, FlowKeyHash> m_activeStreams;
    };

} // namespace Vpn::Client

#endif // _WIN32