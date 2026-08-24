#include "TunToSocksEngine.h"
#include <iostream>
#include <algorithm>

extern "C" {
#include "lwip/opt.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
}

namespace Vpn::Client {

    Tun2SocksEngine::Tun2SocksEngine(boost::asio::io_context& ioContext,
        std::shared_ptr<VpnTransport> transport,
        SendToOsCallback sendToOs)
        : m_ioContext(ioContext),
        m_lwipTimer(ioContext),
        m_transport(std::move(transport)),
        m_sendToOs(std::move(sendToOs)) {
    }

    Tun2SocksEngine::~Tun2SocksEngine() {
        m_lwipTimer.cancel();
    }

    signed char Tun2SocksEngine::LwipNetifInit(struct netif* netif) {
        netif->name[0] = 't';
        netif->name[1] = 'u';
        netif->output = LwipNetifOutput;
        netif->mtu = 1280;
        netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
        return ERR_OK;
    }

    void Tun2SocksEngine::Init() {
        lwip_init();

        m_netif = std::make_unique<struct netif>();

        ip4_addr_t ipaddr, netmask, gw;
        IP4_ADDR(&gw, 10, 8, 0, 2);
        IP4_ADDR(&ipaddr, 10, 8, 0, 1);
        IP4_ADDR(&netmask, 255, 255, 255, 0);

        netif_add(m_netif.get(), &ipaddr, &netmask, &gw, this, LwipNetifInit, ip4_input);
        netif_set_default(m_netif.get());
        netif_set_up(m_netif.get());

        // Настраиваем локальный TCP-слушатель для перехваченных соединений ОС
        struct tcp_pcb* pcb = tcp_new();
        tcp_bind(pcb, IP_ANY_TYPE, 1080);
        pcb = tcp_listen(pcb);
        tcp_arg(pcb, this);
        tcp_accept(pcb, LwipTcpAccept);

        // UDP-сокет через lwIP больше не нужен, так как мы перехватываем весь UDP
        // на входе из TUN-драйвера и инкапсулируем его напрямую в TCP-поток.

        StartLwipTimer();
        std::cout << "[Tun2Socks] Engine initialized successfully with TCP & UDP-over-TCP enforcement!\n";
    }

    void Tun2SocksEngine::StartLwipTimer() {
        m_lwipTimer.expires_after(std::chrono::milliseconds(250));
        m_lwipTimer.async_wait([this](boost::system::error_code ec) {
            if (!ec) {
                sys_check_timeouts();
                CheckUdpTimeouts(); // <--- Добавили очистку неактивных UDP сессий
                StartLwipTimer();
            }
            });
    }

    void Tun2SocksEngine::UpdateChecksums(uint8_t* packet, size_t len, uint16_t ip_header_len) {
        packet[10] = 0; packet[11] = 0;
        uint32_t ip_sum = 0;
        for (int i = 0; i < ip_header_len; i += 2) {
            ip_sum += (packet[i] << 8) | packet[i + 1];
        }
        while (ip_sum >> 16) ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        ip_sum = ~ip_sum;
        packet[10] = (ip_sum >> 8) & 0xFF;
        packet[11] = ip_sum & 0xFF;

        size_t tcp_len = len - ip_header_len;
        if (tcp_len < 20) return;
        packet[ip_header_len + 16] = 0; packet[ip_header_len + 17] = 0;

        uint32_t tcp_sum = 0;
        for (int i = 12; i < 20; i += 2) {
            tcp_sum += (packet[i] << 8) | packet[i + 1];
        }
        tcp_sum += 6;
        tcp_sum += tcp_len;

        for (size_t i = 0; i < tcp_len; i += 2) {
            uint16_t val = (packet[ip_header_len + i] << 8);
            if (i + 1 < tcp_len) val |= packet[ip_header_len + i + 1];
            tcp_sum += val;
        }
        while (tcp_sum >> 16) tcp_sum = (tcp_sum & 0xFFFF) + (tcp_sum >> 16);
        tcp_sum = ~tcp_sum;
        packet[ip_header_len + 16] = (tcp_sum >> 8) & 0xFF;
        packet[ip_header_len + 17] = tcp_sum & 0xFF;
    }

    void Tun2SocksEngine::OnIpPacketFromOs(const uint8_t* data, size_t length) {
        if (length < 20) return;

        uint8_t version_ihl = data[0];
        if ((version_ihl >> 4) != 4) return; // Только IPv4

        uint8_t ihl = version_ihl & 0x0F;
        uint16_t ip_header_len = ihl * 4;
        if (length < ip_header_len) return;

        uint8_t protocol = data[9];

        uint32_t src_ip, dst_ip;
        std::memcpy(&src_ip, data + 12, 4);
        std::memcpy(&dst_ip, data + 16, 4);

        // Фильтрация служебного шума ОС (Multicast, Broadcast, Loopback, шлюз)
        uint8_t first_octet = data[16];
        uint8_t fourth_octet = data[19];
        if (first_octet >= 224 && first_octet <= 239) return; // Multicast
        if (fourth_octet == 255 || dst_ip == 0xFFFFFFFF) return; // Broadcast
        if (first_octet == 127) return; // Loopback

        uint32_t lwip_ip_gateway, client_ip_local;
        ip4addr_aton("10.8.0.1", (ip4_addr_t*)&lwip_ip_gateway);
        ip4addr_aton("10.8.0.2", (ip4_addr_t*)&client_ip_local);
        if (dst_ip == lwip_ip_gateway || dst_ip == client_ip_local) return;

        // ==========================================
        // 1. КОРРЕКТНАЯ ОБРАБОТКА UDP И QUIC ТРАФИКА
        // ==========================================
        if (protocol == 17) { // UDP
            uint16_t src_port_raw, dst_port_raw;
            std::memcpy(&src_port_raw, data + ip_header_len, 2);
            std::memcpy(&dst_port_raw, data + ip_header_len + 2, 2);

            uint16_t src_port = lwip_ntohs(src_port_raw);
            uint16_t dst_port = lwip_ntohs(dst_port_raw);

            uint16_t udp_header_len = 8;
            if (length < ip_header_len + udp_header_len) return;

            const uint8_t* udp_payload = data + ip_header_len + udp_header_len;
            size_t udp_payload_len = length - (ip_header_len + udp_header_len);
            std::vector<uint8_t> payload(udp_payload, udp_payload + udp_payload_len);

            auto it = m_udpSessions.find(src_port);
            std::shared_ptr<UdpSession> session;

            if (it != m_udpSessions.end() && it->second->remoteIp == dst_ip && it->second->remotePort == dst_port) {
                // Сессия существует — обновляем таймер и шлем данные по существующему каналу
                session = it->second;
                session->lastActive = std::chrono::steady_clock::now();
                session->streamChannel->SendData(payload);
            }
            else {
                // Если порт сменил назначение — старую сессию закрываем
                if (it != m_udpSessions.end()) {
                    RemoveUdpSession(src_port);
                }

                // Создаем новый защищенный UDP-поток в туннеле
                auto streamChannel = std::make_shared<VpnStreamChannel>(m_transport);
                uint32_t streamId = streamChannel->GetStreamId();

                session = std::make_shared<UdpSession>();
                session->streamId = streamId;
                session->streamChannel = streamChannel;
                session->clientIp = src_ip;
                session->clientPort = src_port;
                session->remoteIp = dst_ip;
                session->remotePort = dst_port;
                session->lastActive = std::chrono::steady_clock::now();

                m_udpSessions[src_port] = session;
                m_streams[streamId] = streamChannel;

                Protocol::TargetAddress target{ Protocol::AddressType::IPv4 };
                target.address = IpToString(dst_ip);
                target.port = dst_port;
                target.isUdp = true;

                // Регистрируем обработчик входящих ответов от сервера для этого UDP-потока
                streamChannel->RegisterStream([this, src_port](const Protocol::MuxFrame& frame) {
                    OnServerUdpData(src_port, frame);
                    });

                streamChannel->OpenVpnStream(target);
                streamChannel->SendData(payload);
            }
            return;
        }

        // 2. ПЕРЕХВАТ ТСР -> ПЕРЕНАПРАВЛЕНИЕ НА ЛОКАЛЬНЫЙ ПРОКСИ-ПОРТ 1080 (lwIP)
        if (protocol == 6) { // TCP
            uint16_t src_port_raw, dst_port_raw;
            std::memcpy(&src_port_raw, data + ip_header_len, 2);
            std::memcpy(&dst_port_raw, data + ip_header_len + 2, 2);

            uint16_t src_port = lwip_ntohs(src_port_raw);
            uint16_t dst_port = lwip_ntohs(dst_port_raw);

            {
                std::lock_guard<std::mutex> lock(m_engineMutex);
                m_natTable[src_port] = { dst_ip, dst_port };
            }
            std::vector<uint8_t> mod_data(data, data + length);

            uint32_t lwip_ip_target;
            ip4addr_aton("10.8.0.1", (ip4_addr_t*)&lwip_ip_target);
            std::memcpy(mod_data.data() + 16, &lwip_ip_target, 4);

            uint16_t proxy_port = lwip_htons(1080);
            std::memcpy(mod_data.data() + ip_header_len + 2, &proxy_port, 2);

            UpdateChecksums(mod_data.data(), mod_data.size(), ip_header_len);

            struct pbuf* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(mod_data.size()), PBUF_POOL);
            if (p) {
                pbuf_take(p, mod_data.data(), static_cast<u16_t>(mod_data.size()));
                if (m_netif->input(p, m_netif.get()) != ERR_OK) pbuf_free(p);
            }
            return;
        }

        // Прочие протоколы
        struct pbuf* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(length), PBUF_POOL);
        if (p) {
            pbuf_take(p, data, static_cast<u16_t>(length));
            if (m_netif->input(p, m_netif.get()) != ERR_OK) pbuf_free(p);
        }
    }

    signed char Tun2SocksEngine::LwipNetifOutput(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
        auto* engine = static_cast<Tun2SocksEngine*>(netif->state);

        std::vector<uint8_t> buffer(p->tot_len);
        pbuf_copy_partial(p, buffer.data(), p->tot_len, 0);

        if (buffer.size() >= 20 && (buffer[0] >> 4) == 4 && buffer[9] == 6) {
            uint8_t ihl = buffer[0] & 0x0F;
            uint16_t ip_header_len = ihl * 4;

            uint16_t dst_port_raw;
            std::memcpy(&dst_port_raw, buffer.data() + ip_header_len + 2, 2);
            uint16_t dst_port = lwip_ntohs(dst_port_raw);

            std::lock_guard<std::mutex> lock(engine->m_engineMutex);
            auto it = engine->m_natTable.find(dst_port);
            if (it != engine->m_natTable.end()) {
                uint32_t orig_ip = it->second.first;
                uint16_t orig_port = lwip_htons(it->second.second);

                std::memcpy(buffer.data() + 12, &orig_ip, 4);
                std::memcpy(buffer.data() + ip_header_len, &orig_port, 2);

                engine->UpdateChecksums(buffer.data(), buffer.size(), ip_header_len);
            }
        }

        engine->m_sendToOs(buffer.data(), buffer.size());
        return ERR_OK;
    }

    void Tun2SocksEngine::TrySendTcpData(LwipTcpContext* ctx) {
        if (!ctx->pcb) return;

        while (!ctx->txQueue.empty()) {
            auto& data = ctx->txQueue.front();
            u16_t available = tcp_sndbuf(ctx->pcb);

            if (available == 0) break;

            u16_t to_write = std::min(static_cast<u16_t>(data.size()), available);
            err_t err = tcp_write(ctx->pcb, data.data(), to_write, TCP_WRITE_FLAG_COPY);

            if (err == ERR_OK) {
                if (to_write == data.size()) {
                    ctx->txQueue.pop_front();
                }
                else {
                    data.erase(data.begin(), data.begin() + to_write);
                }
            }
            else if (err == ERR_MEM) {
                break;
            }
            else {
                break;
            }
        }
        tcp_output(ctx->pcb);
    }

    void Tun2SocksEngine::OnServerTcpData(uint32_t streamId, const Protocol::MuxFrame& frame) {
        auto it = m_tcpContexts.find(streamId);
        if (it == m_tcpContexts.end() || it->second->pcb == nullptr) return;

        if (frame.command == Protocol::Command::StreamData) {
            it->second->txQueue.push_back(frame.payload);
            TrySendTcpData(it->second.get());
        }
        else if (frame.command == Protocol::Command::StreamHalfClose) {
            if (it->second->pcb) {
                tcp_shutdown(it->second->pcb, 0, 1);
            }
        }
        else if (frame.command == Protocol::Command::StreamClose) {
            RemoveTcpConnection(streamId); // А вот тут убиваем полностью
        }
    }

    void Tun2SocksEngine::RemoveTcpConnection(uint32_t streamId) {
        struct tcp_pcb* pcb_to_close = nullptr;

        {
            // 1. Захватываем мьютекс только для безопасного редактирования мап
            std::lock_guard<std::mutex> lock(m_engineMutex);

            auto streamIt = m_streams.find(streamId);
            if (streamIt != m_streams.end()) {
                streamIt->second->SendCloseAndUnregister();
                m_streams.erase(streamIt);
            }

            auto ctxIt = m_tcpContexts.find(streamId);
            if (ctxIt != m_tcpContexts.end()) {
                if (ctxIt->second->pcb) {
                    uint16_t clientPort = ctxIt->second->pcb->remote_port;
                    m_natTable.erase(clientPort);

                    pcb_to_close = ctxIt->second->pcb;
                    // Отвязываем контекст, чтобы избежать лишних обратных вызовов
                    tcp_arg(pcb_to_close, nullptr);
                    ctxIt->second->pcb = nullptr;
                }
                m_tcpContexts.erase(ctxIt);
            }
        } // <-- lock_guard разрушается здесь, m_engineMutex освобождается

        // 2. Безопасно вызываем tcp_close() уже без удержания мьютекса
        if (pcb_to_close) {
            tcp_close(pcb_to_close);
        }
    }

    std::string Tun2SocksEngine::IpToString(uint32_t ip) {
        uint8_t bytes[4];
        std::memcpy(bytes, &ip, 4);
        return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
            std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
    }

    signed char Tun2SocksEngine::LwipTcpAccept(void* arg, struct tcp_pcb* newpcb, signed char err) {
        if (!arg || !newpcb || err != ERR_OK) {
            return ERR_VAL;
        }

        auto* engine = static_cast<Tun2SocksEngine*>(arg);

        auto streamChannel = std::make_shared<VpnStreamChannel>(engine->m_transport);
        uint32_t streamId = streamChannel->GetStreamId();

        auto ctx = std::make_unique<LwipTcpContext>();
        ctx->engine = engine;
        ctx->streamId = streamId;
        ctx->pcb = newpcb;

        tcp_arg(newpcb, ctx.get());
        tcp_recv(newpcb, LwipTcpRecv);
        tcp_sent(newpcb, LwipTcpSent);
        tcp_err(newpcb, LwipTcpError);

        engine->m_tcpContexts[streamId] = std::move(ctx);
        engine->m_streams[streamId] = streamChannel;

        Protocol::TargetAddress target{ Protocol::AddressType::IPv4 };

        {
            std::lock_guard<std::mutex> lock(engine->m_engineMutex);
            auto natIt = engine->m_natTable.find(newpcb->remote_port);
            if (natIt != engine->m_natTable.end()) {
                target.address = engine->IpToString(natIt->second.first);
                target.port = natIt->second.second;
            }
            else {
                char ipStr[16];
                ip4addr_ntoa_r(&newpcb->local_ip, ipStr, sizeof(ipStr));
                target.address = ipStr;
                target.port = newpcb->local_port;
            }
        }

        streamChannel->RegisterStream([engine, streamId](const Protocol::MuxFrame& frame) {
            engine->OnServerTcpData(streamId, frame);
            });

        streamChannel->OpenVpnStream(target);

        return ERR_OK;
    }

    signed char Tun2SocksEngine::LwipTcpRecv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, signed char err) {
        auto* ctx = static_cast<LwipTcpContext*>(arg);
        if (!ctx) return ERR_OK;

        if (p == nullptr) {
            ctx->engine->RemoveTcpConnection(ctx->streamId);
            return ERR_OK;
        }

        auto it = ctx->engine->m_streams.find(ctx->streamId);
        if (it != ctx->engine->m_streams.end()) {
            std::vector<uint8_t> payload(p->tot_len);
            pbuf_copy_partial(p, payload.data(), p->tot_len, 0);
            it->second->SendData(payload);
        }

        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
        return ERR_OK;
    }

    signed char Tun2SocksEngine::LwipTcpSent(void* arg, struct tcp_pcb* tpcb, u16_t len) {
        auto* ctx = static_cast<LwipTcpContext*>(arg);
        if (ctx) {
            ctx->engine->TrySendTcpData(ctx);
        }
        return ERR_OK;
    }

    void Tun2SocksEngine::LwipTcpError(void* arg, signed char err) {
        auto* ctx = static_cast<LwipTcpContext*>(arg);
        if (ctx) {
            ctx->pcb = nullptr;
            ctx->engine->RemoveTcpConnection(ctx->streamId);
        }
    }

    void Tun2SocksEngine::OnServerUdpData(uint16_t clientPort, const Protocol::MuxFrame& frame) {
        auto it = m_udpSessions.find(clientPort);
        if (it == m_udpSessions.end()) return;

        auto& session = it->second;
        session->lastActive = std::chrono::steady_clock::now();

        if (frame.command == Protocol::Command::StreamData) {
            const auto& payload = frame.payload;
            size_t ip_header_len = 20;
            size_t udp_header_len = 8;
            size_t total_len = ip_header_len + udp_header_len + payload.size();

            std::vector<uint8_t> packet(total_len, 0);

            // Формируем IPv4 заголовок для пакета, идущего обратно ОС от удаленного сервера
            packet[0] = (4 << 4) | 5; // IPv4, IHL 5
            packet[1] = 0;
            packet[2] = (total_len >> 8) & 0xFF;
            packet[3] = total_len & 0xFF;
            packet[8] = 64; // TTL
            packet[9] = 17; // Протокол UDP

            // Source IP = IP реального сервера, Destination IP = локальный IP клиента (10.8.0.2)
            std::memcpy(packet.data() + 12, &session->remoteIp, 4);
            std::memcpy(packet.data() + 16, &session->clientIp, 4);

            // UDP заголовок
            uint16_t src_port_net = lwip_htons(session->remotePort);
            uint16_t dst_port_net = lwip_htons(session->clientPort);
            uint16_t udp_len_net = lwip_htons(udp_header_len + payload.size());

            std::memcpy(packet.data() + 20, &src_port_net, 2);
            std::memcpy(packet.data() + 22, &dst_port_net, 2);
            std::memcpy(packet.data() + 24, &udp_len_net, 2);
            // Контрольная сумма UDP в IPv4 может быть равна 0

            // Копируем полезную нагрузку (payload)
            std::memcpy(packet.data() + 28, payload.data(), payload.size());

            // Пересчитываем контрольную сумму IP-заголовка
            UpdateChecksums(packet.data(), packet.size(), ip_header_len);

            // Передаем готовый пакет обратно в операционную систему через TUN-драйвер
            m_sendToOs(packet.data(), packet.size());
        }
        else if (frame.command == Protocol::Command::StreamClose || frame.command == Protocol::Command::StreamHalfClose) {
            RemoveUdpSession(clientPort);
        }
    }

    void Tun2SocksEngine::RemoveUdpSession(uint16_t clientPort) {
        auto it = m_udpSessions.find(clientPort);
        if (it != m_udpSessions.end()) {
            uint32_t streamId = it->second->streamId;
            m_streams.erase(streamId);
            m_udpSessions.erase(it);
        }
    }

    void Tun2SocksEngine::CheckUdpTimeouts() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = m_udpSessions.begin(); it != m_udpSessions.end(); ) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it->second->lastActive).count();
            if (duration > 60) { // Закрываем UDP-сессию после 30 секунд неактивности
                it->second->streamChannel->SendCloseAndUnregister();
                uint32_t streamId = it->second->streamId;
                m_streams.erase(streamId);
                it = m_udpSessions.erase(it);
            }
            else {
                ++it;
            }
        }
    }

} // namespace Vpn::Client