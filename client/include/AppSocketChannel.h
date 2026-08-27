#pragma once
#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <deque>
#include <array>
#include <atomic>
#include <boost/asio/steady_timer.hpp>

namespace Vpn::Client {

    using BackpressureCheck = std::function<bool()>;
    using boost::asio::ip::tcp;
    

    class AppSocketChannel : public std::enable_shared_from_this<AppSocketChannel> {
    public:
        using DataCallback = std::function<void(const std::vector<uint8_t>& data)>;
        using HalfCloseCallback = std::function<void()>;
        using ErrorCallback = std::function<void()>;
        void StartReading(uint32_t streamId, DataCallback onData, HalfCloseCallback onHalfClose, ErrorCallback onError, BackpressureCheck isCongested = nullptr);

        explicit AppSocketChannel(tcp::socket socket);

        void Write(uint32_t streamId, const uint8_t* data, size_t length, ErrorCallback onError);
        void ShutdownSend();
        void Close();

        tcp::socket& GetSocket() { return m_appSocket; }

    private:
        void DoReadFromApp();
        void DoWriteToAppQueue(uint32_t streamId, ErrorCallback onError);

        tcp::socket m_appSocket;
        std::array<uint8_t, 8192> m_appBuf{};

        std::deque<std::shared_ptr<std::vector<uint8_t>>> m_writeQueue;
        bool m_isWriting{ false };
        bool m_isHalfClosed{ false };

        uint32_t m_streamId{ 0 };
        DataCallback m_onData;
        HalfCloseCallback m_onHalfClose;
        ErrorCallback m_onError;

        BackpressureCheck m_isCongested;
        std::unique_ptr<boost::asio::steady_timer> m_backpressureTimer;
        std::atomic<size_t> m_pendingAppWriteBytes{ 0 };
    };

} // namespace Vpn::Client