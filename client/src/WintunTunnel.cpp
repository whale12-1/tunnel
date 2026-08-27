#ifdef _WIN32

#include "WintunTunnel.h"
#include <iostream>

// Указатели на функции Wintun API
typedef WINTUN_ADAPTER_HANDLE(WINAPI* WintunCreateAdapterPtr)(PCWSTR, PCWSTR, const GUID*);
typedef void(WINAPI* WintunCloseAdapterPtr)(WINTUN_ADAPTER_HANDLE);
typedef WINTUN_SESSION_HANDLE(WINAPI* WintunStartSessionPtr)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef void(WINAPI* WintunEndSessionPtr)(WINTUN_SESSION_HANDLE);
typedef HANDLE(WINAPI* WintunGetReadWaitEventPtr)(WINTUN_SESSION_HANDLE);
typedef BYTE* (WINAPI* WintunReceivePacketPtr)(WINTUN_SESSION_HANDLE, DWORD*);
typedef void(WINAPI* WintunReleaseReceivePacketPtr)(WINTUN_SESSION_HANDLE, const BYTE*);
typedef BYTE* (WINAPI* WintunAllocateSendPacketPtr)(WINTUN_SESSION_HANDLE, DWORD);
typedef void(WINAPI* WintunSendPacketPtr)(WINTUN_SESSION_HANDLE, const BYTE*);
typedef void(WINAPI* WintunGetAdapterLUIDPtr)(WINTUN_ADAPTER_HANDLE, NET_LUID*);

static WintunCreateAdapterPtr pfnWintunCreateAdapter = nullptr;
static WintunCloseAdapterPtr pfnWintunCloseAdapter = nullptr;
static WintunStartSessionPtr pfnWintunStartSession = nullptr;
static WintunEndSessionPtr pfnWintunEndSession = nullptr;
static WintunGetReadWaitEventPtr pfnWintunGetReadWaitEvent = nullptr;
static WintunReceivePacketPtr pfnWintunReceivePacket = nullptr;
static WintunReleaseReceivePacketPtr pfnWintunReleaseReceivePacket = nullptr;
static WintunAllocateSendPacketPtr pfnWintunAllocateSendPacket = nullptr;
static WintunSendPacketPtr pfnWintunSendPacket = nullptr;
static WintunGetAdapterLUIDPtr pfnWintunGetAdapterLUID = nullptr;

namespace Vpn::Client {

    WintunTunnel::WintunTunnel(boost::asio::io_context& ioContext, std::shared_ptr<VpnTransport> transport)
        : m_ioContext(ioContext), m_transport(std::move(transport)) {
    }

    WintunTunnel::~WintunTunnel() {
        // 1. Ожидаем завершения и отменяем все асинхронные задачи
        Stop();

        // 2. Только после полной остановки и отмены хэндлеров выгружаем DLL
        if (m_wintunDll) {
            FreeLibrary(m_wintunDll);
            m_wintunDll = nullptr;
        }
    }

    bool WintunTunnel::LoadWintunFunctions() {
        if (m_wintunDll) return true;

        m_wintunDll = LoadLibraryW(L"wintun.dll");
        if (!m_wintunDll) {
            std::cerr << "[Wintun Error] Could not load wintun.dll. Make sure wintun.dll is in executable path!\n";
            return false;
        }

        pfnWintunCreateAdapter = (WintunCreateAdapterPtr)GetProcAddress(m_wintunDll, "WintunCreateAdapter");
        pfnWintunCloseAdapter = (WintunCloseAdapterPtr)GetProcAddress(m_wintunDll, "WintunCloseAdapter");
        pfnWintunStartSession = (WintunStartSessionPtr)GetProcAddress(m_wintunDll, "WintunStartSession");
        pfnWintunEndSession = (WintunEndSessionPtr)GetProcAddress(m_wintunDll, "WintunEndSession");
        pfnWintunGetReadWaitEvent = (WintunGetReadWaitEventPtr)GetProcAddress(m_wintunDll, "WintunGetReadWaitEvent");
        pfnWintunReceivePacket = (WintunReceivePacketPtr)GetProcAddress(m_wintunDll, "WintunReceivePacket");
        pfnWintunReleaseReceivePacket = (WintunReleaseReceivePacketPtr)GetProcAddress(m_wintunDll, "WintunReleaseReceivePacket");
        pfnWintunAllocateSendPacket = (WintunAllocateSendPacketPtr)GetProcAddress(m_wintunDll, "WintunAllocateSendPacket");
        pfnWintunSendPacket = (WintunSendPacketPtr)GetProcAddress(m_wintunDll, "WintunSendPacket");
        pfnWintunGetAdapterLUID = (WintunGetAdapterLUIDPtr)GetProcAddress(m_wintunDll, "WintunGetAdapterLUID");

        return pfnWintunCreateAdapter && pfnWintunStartSession && pfnWintunGetReadWaitEvent &&
            pfnWintunReceivePacket && pfnWintunAllocateSendPacket && pfnWintunSendPacket && pfnWintunGetAdapterLUID;
    }

    bool WintunTunnel::InitAdapter(const std::wstring& adapterName) {
        if (!LoadWintunFunctions()) return false;

        GUID exampleGuid = { 0xdeadbeef, 0x1234, 0x5678, { 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44 } };
        m_adapter = pfnWintunCreateAdapter(adapterName.c_str(), L"Custom VPN Adapter", &exampleGuid);

        if (!m_adapter) {
            std::cerr << "[Wintun Error] Failed to create Wintun adapter (Run as Administrator!)\n";
            return false;
        }

        pfnWintunGetAdapterLUID(m_adapter, &m_luid);

        m_session = pfnWintunStartSession(m_adapter, 0x400000);
        if (!m_session) {
            std::cerr << "[Wintun Error] Failed to start Wintun session.\n";
            pfnWintunCloseAdapter(m_adapter);
            m_adapter = nullptr;
            return false;
        }

        HANDLE waitEvent = pfnWintunGetReadWaitEvent(m_session);
        HANDLE duplicatedWaitEvent = NULL;

        // Дублируем дескриптор для Boost.Asio
        DuplicateHandle(
            GetCurrentProcess(), waitEvent,
            GetCurrentProcess(), &duplicatedWaitEvent,
            0, FALSE, DUPLICATE_SAME_ACCESS
        );

        // Теперь Asio владеет только копией
        m_readWaitEvent = std::make_unique<boost::asio::windows::object_handle>(m_ioContext, duplicatedWaitEvent);

        std::cout << "[Wintun] Adapter initialized successfully!\n";
        return true;
    }

    void WintunTunnel::SetupRouting(const std::string& serverHost) {
        std::cout << "[Wintun] Configuring system IP address and routing via IP Helper API...\n";

        // 1. Синхронно резолвим домен, чтобы скормить Windows чистый IPv4
        boost::asio::ip::tcp::resolver resolver(m_ioContext);
        boost::system::error_code ec;
        auto results = resolver.resolve(serverHost, "", ec);

        std::string resolvedIp = serverHost; // По умолчанию оставляем как есть (если это уже IP)
        if (!ec && !results.empty()) {
            for (const auto& res : results) {
                if (res.endpoint().address().is_v4()) {
                    resolvedIp = res.endpoint().address().to_v4().to_string();
                    break;
                }
            }
        }
        else if (ec) {
            std::cerr << "[Wintun Warning] Routing DNS resolve failed: " << ec.message() << "\n";
        }

        m_serverIp = resolvedIp;
        std::cout << "[Wintun] Target routing IP resolved to: " << m_serverIp << "\n";

        MIB_UNICASTIPADDRESS_ROW ipRow;
        InitializeUnicastIpAddressEntry(&ipRow);
        ipRow.InterfaceLuid = m_luid;
        ipRow.Address.Ipv4.sin_family = AF_INET;
        inet_pton(AF_INET, "10.8.0.2", &ipRow.Address.Ipv4.sin_addr);
        ipRow.OnLinkPrefixLength = 24;

        DWORD status = CreateUnicastIpAddressEntry(&ipRow);
        if (status != ERROR_SUCCESS && status != ERROR_OBJECT_ALREADY_EXISTS) {
            std::cerr << "[Wintun Error] Failed to assign IP to adapter. Error code: " << status << "\n";
            return;
        }

        if (m_serverIp != "127.0.0.1" && m_serverIp != "localhost" && m_serverIp != "::1") {
            SOCKADDR_INET serverAddr{};
            serverAddr.Ipv4.sin_family = AF_INET;
            inet_pton(AF_INET, m_serverIp.c_str(), &serverAddr.Ipv4.sin_addr);

            MIB_IPFORWARD_ROW2 bestRoute{};
            SOCKADDR_INET bestNextHop{};

            if (GetBestRoute2(NULL, 0, NULL, &serverAddr, 0, &bestRoute, &bestNextHop) == NO_ERROR) {
                MIB_IPFORWARD_ROW2 serverRoute{};
                InitializeIpForwardEntry(&serverRoute);
                serverRoute.InterfaceLuid = bestRoute.InterfaceLuid;
                serverRoute.InterfaceIndex = bestRoute.InterfaceIndex;
                serverRoute.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
                inet_pton(AF_INET, m_serverIp.c_str(), &serverRoute.DestinationPrefix.Prefix.Ipv4.sin_addr);
                serverRoute.DestinationPrefix.PrefixLength = 32;
                serverRoute.NextHop = bestNextHop;
                serverRoute.Metric = 1;

                CreateIpForwardEntry2(&serverRoute);
            }
        }

        auto addTunnelRoute = [this](const char* prefix, UINT8 prefixLen) {
            MIB_IPFORWARD_ROW2 route{};
            InitializeIpForwardEntry(&route);
            route.InterfaceLuid = m_luid;
            route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            inet_pton(AF_INET, prefix, &route.DestinationPrefix.Prefix.Ipv4.sin_addr);
            route.DestinationPrefix.PrefixLength = prefixLen;
            route.Metric = 1;

            CreateIpForwardEntry2(&route);
            };

        addTunnelRoute("0.0.0.0", 1);
        addTunnelRoute("128.0.0.0", 1);

        std::cout << "[Wintun] Native routing updated successfully!\n";
    }

    void WintunTunnel::ClearRouting() {
        std::cout << "[Wintun] Restoring original routing...\n";

        auto deleteTunnelRoute = [this](const char* prefix, UINT8 prefixLen) {
            MIB_IPFORWARD_ROW2 route{};
            InitializeIpForwardEntry(&route);
            route.InterfaceLuid = m_luid;
            route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            inet_pton(AF_INET, prefix, &route.DestinationPrefix.Prefix.Ipv4.sin_addr);
            route.DestinationPrefix.PrefixLength = prefixLen;

            DeleteIpForwardEntry2(&route);
            };

        deleteTunnelRoute("0.0.0.0", 1);
        deleteTunnelRoute("128.0.0.0", 1);

        if (!m_serverIp.empty() && m_serverIp != "127.0.0.1" && m_serverIp != "localhost" && m_serverIp != "::1") {
            MIB_IPFORWARD_ROW2 route{};
            InitializeIpForwardEntry(&route);
            route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            inet_pton(AF_INET, m_serverIp.c_str(), &route.DestinationPrefix.Prefix.Ipv4.sin_addr);
            route.DestinationPrefix.PrefixLength = 32;

            DeleteIpForwardEntry2(&route);
        }
    }

    void WintunTunnel::Start() {
        m_isStopping = false;
        if (!m_session || !m_readWaitEvent) return;

        m_engine = std::make_shared<Tun2SocksEngine>(
            m_ioContext,
            m_transport,
            [this](const uint8_t* data, size_t len) {
                SendPacketToOs(data, len);
            }
        );
        m_engine->Init();

        DoAsyncRead();
    }

    void WintunTunnel::ReadPackets() {
        DWORD packetSize = 0;
        while (!m_isStopping && m_session && pfnWintunReceivePacket) {
            BYTE* packet = pfnWintunReceivePacket(m_session, &packetSize);
            if (!packet) break;

            ProcessIpPacket(packet, packetSize);

            if (m_session && pfnWintunReleaseReceivePacket) {
                pfnWintunReleaseReceivePacket(m_session, packet);
            }
        }
    }

    void WintunTunnel::DoAsyncRead() {
        if (m_isStopping || !m_readWaitEvent) return;

        auto self = shared_from_this();
        m_readWaitEvent->async_wait([this, self](boost::system::error_code ec) {
            // Если была отмена через Stop() или операция отменена ОС — выходим
            if (ec == boost::asio::error::operation_aborted || ec || m_isStopping) {
                return;
            }

            ReadPackets();

            if (!m_isStopping) {
                DoAsyncRead();
            }
            });
    }

    void WintunTunnel::ProcessIpPacket(const uint8_t* packetData, size_t length) {
        if (m_transport && m_transport->IsCongested()) {
            return;
        }
        if (!m_isStopping && m_engine) {
            m_engine->OnIpPacketFromOs(packetData, length);
        }
    }

    void WintunTunnel::SendPacketToOs(const uint8_t* data, size_t length) {
        if (m_isStopping || !m_session || !pfnWintunAllocateSendPacket || !pfnWintunSendPacket) return;

        BYTE* sendPacket = pfnWintunAllocateSendPacket(m_session, static_cast<DWORD>(length));
        if (sendPacket) {
            std::memcpy(sendPacket, data, length);
            pfnWintunSendPacket(m_session, sendPacket);
        }
    }

    void WintunTunnel::Stop() {
        // Атомарно гарантируем, что Stop() выполнится только один раз
        bool expected = false;
        if (!m_isStopping.compare_exchange_strong(expected, true)) {
            return;
        }

        // 1. Завершаем сессию Wintun (драйвер отпускает системный event)
        if (m_session && pfnWintunEndSession) {
            pfnWintunEndSession(m_session);
            m_session = nullptr;
        }

        // 2. Отменяем и закрываем хэндл асинхронного ожидания в Boost.Asio
        if (m_readWaitEvent) {
            boost::system::error_code ec;
            m_readWaitEvent->cancel(ec); // Переводит колбэки в состояние operation_aborted
            m_readWaitEvent->close(ec);  // Закрывает HANDLE на уровне Windows
            m_readWaitEvent.reset();
        }

        // 3. Закрываем сам адаптер
        if (m_adapter && pfnWintunCloseAdapter) {
            pfnWintunCloseAdapter(m_adapter);
            m_adapter = nullptr;
        }

        // 4. Очищаем движок tun2socks после остановки ввода-вывода
        if (m_engine) {
            m_engine.reset();
        }
    }

} // namespace Vpn::Client

#endif // _WIN32