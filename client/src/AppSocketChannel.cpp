#include "AppSocketChannel.h"
#include <iostream>

namespace Vpn::Client {

    AppSocketChannel::AppSocketChannel(tcp::socket socket)
        : m_appSocket(std::move(socket)) {
    }

    void AppSocketChannel::StartReading(uint32_t streamId, DataCallback onData, HalfCloseCallback onHalfClose, ErrorCallback onError, BackpressureCheck isCongested) {
        m_streamId = streamId;
        m_onData = std::move(onData);
        m_onHalfClose = std::move(onHalfClose);
        m_onError = std::move(onError);

        // --- ДОБАВЛЕНО ---
        m_isCongested = std::move(isCongested);
        m_backpressureTimer = std::make_unique<boost::asio::steady_timer>(m_appSocket.get_executor());
        // -----------------

        DoReadFromApp();
    }

    void AppSocketChannel::DoReadFromApp() {
        auto self = shared_from_this();
        if (m_isHalfClosed) return;

        // --- ДОБАВЛЕНО: Пауза при перегрузке VPN-канала ---
        if (m_isCongested && m_isCongested()) {
            m_backpressureTimer->expires_after(std::chrono::milliseconds(50));
            m_backpressureTimer->async_wait([this, self](boost::system::error_code ec) {
                if (!ec && !m_isHalfClosed) DoReadFromApp(); // Пробуем снова через 50мс
                });
            return;
        }


        m_appSocket.async_read_some(
            boost::asio::buffer(m_appBuf),
            [this, self](boost::system::error_code ec, size_t length) {

                if (ec) {
                    if (ec == boost::asio::error::eof ||
                        ec.value() == 1236 || ec.value() == 10053 || ec.value() == 995) {

                        std::cout << "[Client Proxy] App finished sending data (Stream #"
                            << m_streamId << "). Sending HalfClose.\n";

                        m_isHalfClosed = true;
                        if (m_onHalfClose) m_onHalfClose();

                        boost::system::error_code shutdownEc;
                        m_appSocket.shutdown(tcp::socket::shutdown_send, shutdownEc);
                        return;
                    }

                    std::cerr << "[Client Proxy Error] Fatal read from app: " << ec.message() << "\n";
                    if (m_onError) m_onError();
                    return;
                }

                if (length > 0) {
                    std::vector<uint8_t> data(m_appBuf.begin(), m_appBuf.begin() + length);
                    if (m_onData) m_onData(data);
                    DoReadFromApp();
                }
            }
        );
    }

    void AppSocketChannel::Write(uint32_t streamId, const uint8_t* data, size_t length, ErrorCallback onError) {
        // --- ДОБАВЛЕНО: Hard-Limit при скачивании (Защита от OOM) ---
        m_pendingAppWriteBytes += length;
        if (m_pendingAppWriteBytes > 16 * 1024 * 1024) { // Максимум 16 МБ буфера на один поток
            std::cerr << "[Client Proxy] App stream buffer overflow. Dropping connection.\n";
            if (onError) onError();
            return;
        }
        // ------------------------------------------------------------

        m_writeQueue.push_back(std::make_shared<std::vector<uint8_t>>(data, data + length));
        if (!m_isWriting) {
            DoWriteToAppQueue(streamId, std::move(onError));
        }
    }

    void AppSocketChannel::DoWriteToAppQueue(uint32_t streamId, ErrorCallback onError) {
        if (m_writeQueue.empty()) {
            m_isWriting = false;
            return;
        }

        m_isWriting = true;
        auto self = shared_from_this();
        auto bufferPtr = m_writeQueue.front();

        boost::asio::async_write(m_appSocket, boost::asio::buffer(*bufferPtr),
            [this, self, streamId, onError  = std::move(onError),bufferPtr](boost::system::error_code ec, size_t) {
                m_pendingAppWriteBytes -= bufferPtr->size();
                if (ec) {
                    std::cerr << "[Client Proxy Error] Write to app (curl) failed on stream #" << streamId
                        << ": " << ec.message() << "\n";
                    if (onError) onError();
                    return;
                }

                m_writeQueue.pop_front();
                DoWriteToAppQueue(streamId, onError);
            });
    }

    void AppSocketChannel::ShutdownSend() {
        boost::system::error_code ec;
        m_appSocket.shutdown(tcp::socket::shutdown_send, ec);
    }

    void AppSocketChannel::Close() {
        m_writeQueue.clear();
        m_isWriting = false;

        boost::system::error_code ec;
        if (m_appSocket.is_open()) {
            m_appSocket.close(ec);
        }
    }

} // namespace Vpn::Client