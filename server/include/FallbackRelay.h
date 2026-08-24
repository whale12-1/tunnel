#pragma once
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <string>
#include <unordered_set>

namespace Vpn::Server {

    using boost::asio::ip::tcp;

    class FallbackRelay : public std::enable_shared_from_this<FallbackRelay> {
    public:
        explicit FallbackRelay(tcp::socket clientSocket);

        void Start(std::shared_ptr<std::vector<uint8_t>> initialPacket);

    private:
        void StartRawRelaying();
        void RelayClientToFallback();
        void RelayFallbackToClient();
        void CloseAll();

        tcp::socket m_clientSocket;
        tcp::socket m_fallbackSocket;

        std::array<uint8_t, 8192> m_c2fBuffer{};
        std::array<uint8_t, 8192> m_f2cBuffer{};
    };

} // namespace Vpn::Server