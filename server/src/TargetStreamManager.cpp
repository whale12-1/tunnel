#include "TargetStreamManager.h"
#include <iostream>

namespace Vpn::Server {

    TargetStreamManager::TargetStreamManager(boost::asio::any_io_executor executor, SendMuxFrameFn sendFn)
        : m_executor(std::move(executor)), m_sendFn(std::move(sendFn)) {
    }

    void TargetStreamManager::ProcessMuxFrame(const Protocol::MuxFrame& frame) {
        switch (frame.command) {
        case Protocol::Command::StreamOpen: HandleStreamOpen(frame.streamId, frame.payload); break;
        case Protocol::Command::StreamData: HandleStreamData(frame.streamId, frame.payload); break;
        case Protocol::Command::StreamHalfClose: HandleStreamHalfClose(frame.streamId); break;
        case Protocol::Command::StreamClose: HandleStreamClose(frame.streamId); break;
        default: break;
        }
    }

    void TargetStreamManager::RefreshUdpTimeout(std::shared_ptr<RemoteStream> stream) {
        if (!stream->isUdp) return;

        boost::system::error_code ec;
        stream->udpIdleTimer.expires_after(std::chrono::seconds(30));

        auto self = shared_from_this();
        stream->udpIdleTimer.async_wait([this, self, streamId = stream->streamId](boost::system::error_code ec) {
            if (!ec) {
                std::cout << "[Server] UDP Stream #" << streamId << " idle timeout. Closing...\n";
                CloseStream(streamId);
            }
        });
    }

    void TargetStreamManager::HandleStreamOpen(uint32_t streamId, const std::vector<uint8_t>& payload) {
        Protocol::TargetAddress target;
        if (!Protocol::StreamFrameHelper::DeserializeTargetAddress(payload.data(), payload.size(), target)) {
            m_sendFn(streamId, Protocol::Command::StreamClose, {}, false);
            return;
        }

        auto stream = std::make_shared<RemoteStream>(streamId, m_executor);
        m_streams[streamId] = stream;
        stream->isUdp = target.isUdp;
        stream->isInteractive = target.isInteractive; // Сохраняем признак интерактивности

        auto self = shared_from_this();

        if (stream->isUdp) {
            auto resolver = std::make_shared<udp::resolver>(m_executor);
            resolver->async_resolve(target.address, std::to_string(target.port),
                [this, self, stream, resolver](boost::system::error_code ec, udp::resolver::results_type endpoints) {
                    if (ec || endpoints.begin() == endpoints.end()) {
                        CloseStream(stream->streamId);
                        return;
                    }

                    stream->remoteUdpEndpoint = *endpoints.begin();
                    boost::system::error_code socketEc;

                    stream->udpSocket.open(stream->remoteUdpEndpoint.protocol(), socketEc);

                    if (!socketEc) {
                        stream->udpSocket.connect(stream->remoteUdpEndpoint, socketEc);
                    }

                    if (socketEc) {
                        std::cerr << "[Server ERROR] Failed to open/connect UDP socket: " << socketEc.message() << "\n";
                        CloseStream(stream->streamId);
                        return;
                    }

                    stream->isConnected = true;
                    RefreshUdpTimeout(stream);

                    m_sendFn(stream->streamId, Protocol::Command::StreamOpen, { 0x00 }, stream->isInteractive);
                    DoReadFromUdpTarget(stream);

                    if (!stream->writeQueue.empty() && !stream->isWriting) {
                        DoWriteToUdpTarget(stream);
                    }
                });
        }
        else {
            std::cout << "[Server] Mux Stream #" << streamId << " requesting TCP connection to "
                << target.address << ":" << target.port
                << " (Interactive: " << (stream->isInteractive ? "true" : "false") << ")\n";

            auto connectTimer = std::make_shared<boost::asio::steady_timer>(m_executor);
            auto resolver = std::make_shared<tcp::resolver>(m_executor);
            auto isDone = std::make_shared<bool>(false);

            connectTimer->expires_after(std::chrono::seconds(4));
            connectTimer->async_wait([this, self, streamId, stream, resolver, isDone](boost::system::error_code ec) {
                if (!ec && !(*isDone)) {
                    *isDone = true;
                    std::cerr << "[Server] Stream #" << streamId << " connection timeout (4s)\n";

                    boost::system::error_code cancelEc;
                    resolver->cancel();
                    if (stream->targetSocket.is_open()) {
                        stream->targetSocket.close(cancelEc);
                    }
                    CloseStream(streamId);
                }
                });

            auto onConnected = [this, self, streamId, stream, connectTimer, isDone](boost::system::error_code ec) {
                if (*isDone) return;
                *isDone = true;

                boost::system::error_code timerEc;
                connectTimer->cancel(timerEc);

                if (ec) {
                    if (ec != boost::asio::error::operation_aborted) {
                        std::cerr << "[Server ERROR] Stream #" << streamId << " TCP connect failed: " << ec.message() << "\n";
                    }
                    CloseStream(streamId);
                    return;
                }

                boost::system::error_code optionEc;
                stream->targetSocket.set_option(tcp::no_delay(true), optionEc);

                stream->isConnected = true;

                m_sendFn(streamId, Protocol::Command::StreamOpen, { 0x00 }, stream->isInteractive);
                DoReadFromTarget(stream);

                if (!stream->writeQueue.empty() && !stream->isWriting) {
                    DoWriteToTarget(stream);
                }
            };

            if (target.type == Protocol::AddressType::IPv4) {
                boost::system::error_code ec;
                auto ipAddr = boost::asio::ip::make_address_v4(target.address, ec);
                if (ec) {
                    boost::system::error_code timerEc;
                    connectTimer->cancel(timerEc);
                    CloseStream(streamId);
                    return;
                }
                stream->targetSocket.async_connect(tcp::endpoint(ipAddr, target.port), onConnected);
            }
            else {
                resolver->async_resolve(target.address, std::to_string(target.port),
                    [this, self, stream, resolver, onConnected, connectTimer, isDone](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                        if (*isDone) return;

                        if (ec) {
                            *isDone = true;
                            boost::system::error_code timerEc;
                            connectTimer->cancel(timerEc);
                            CloseStream(stream->streamId);
                            return;
                        }

                        boost::asio::async_connect(stream->targetSocket, endpoints,
                            [onConnected](boost::system::error_code connectEc, const tcp::endpoint&) {
                                onConnected(connectEc);
                            });
                    });
            }
        }
    }

    void TargetStreamManager::HandleStreamData(uint32_t streamId, const std::vector<uint8_t>& payload) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) return;

        auto stream = it->second;
        stream->writeQueue.push_back(std::make_shared<std::vector<uint8_t>>(payload));

        if (!stream->isWriting) {
            if (stream->isUdp) {
                if (stream->isConnected) DoWriteToUdpTarget(stream);
            }
            else {
                if (stream->isConnected) DoWriteToTarget(stream);
            }
        }
    }

    void TargetStreamManager::DoWriteToUdpTarget(std::shared_ptr<RemoteStream> stream) {
        if (stream->writeQueue.empty()) {
            stream->isWriting = false;
            return;
        }

        stream->isWriting = true;
        RefreshUdpTimeout(stream);

        auto self = shared_from_this();
        auto bufferPtr = stream->writeQueue.front();

        stream->udpSocket.async_send(
            boost::asio::buffer(*bufferPtr),
            [this, self, stream, bufferPtr](boost::system::error_code ec, size_t) {
                if (ec) {
                    CloseStream(stream->streamId);
                    return;
                }
                stream->writeQueue.pop_front();
                DoWriteToUdpTarget(stream);
            });
    }

    void TargetStreamManager::DoReadFromUdpTarget(std::shared_ptr<RemoteStream> stream) {
        auto self = shared_from_this();
        stream->udpSocket.async_receive(
            boost::asio::buffer(stream->readBuffer),
            [this, self, stream](boost::system::error_code ec, size_t bytesTransferred) {
                if (ec) {
                    CloseStream(stream->streamId);
                    return;
                }

                RefreshUdpTimeout(stream);

                std::vector<uint8_t> payload(stream->readBuffer.begin(), stream->readBuffer.begin() + bytesTransferred);
                m_sendFn(stream->streamId, Protocol::Command::StreamData, payload, stream->isInteractive);

                DoReadFromUdpTarget(stream);
            });
    }

    void TargetStreamManager::DoWriteToTarget(std::shared_ptr<RemoteStream> stream) {
        if (stream->writeQueue.empty()) {
            stream->isWriting = false;
            if (stream->clientFinished || stream->targetFinished) {
                CloseStream(stream->streamId);
            }
            return;
        }

        stream->isWriting = true;
        auto self = shared_from_this();
        auto bufferPtr = stream->writeQueue.front();

        boost::asio::async_write(stream->targetSocket, boost::asio::buffer(*bufferPtr),
            [this, self, stream, bufferPtr](boost::system::error_code ec, size_t) {
                if (ec) { CloseStream(stream->streamId); return; }
                stream->writeQueue.pop_front();
                DoWriteToTarget(stream);
            });
    }

    void TargetStreamManager::DoReadFromTarget(std::shared_ptr<RemoteStream> stream) {
        auto self = shared_from_this();
        stream->targetSocket.async_read_some(boost::asio::buffer(stream->readBuffer),
            [this, self, stream](boost::system::error_code ec, size_t bytesTransferred) {
                if (ec) {
                    if (ec == boost::asio::error::eof && !stream->targetFinished) {
                        stream->targetFinished = true;
                        m_sendFn(stream->streamId, Protocol::Command::StreamHalfClose, {}, stream->isInteractive);

                        if (stream->clientFinished && stream->writeQueue.empty() && !stream->isWriting) {
                            CloseStream(stream->streamId);
                        }
                        return;
                    }
                    CloseStream(stream->streamId);
                    return;
                }

                std::vector<uint8_t> payload(stream->readBuffer.begin(), stream->readBuffer.begin() + bytesTransferred);
                m_sendFn(stream->streamId, Protocol::Command::StreamData, payload, stream->isInteractive);
                DoReadFromTarget(stream);
            });
    }

    void TargetStreamManager::HandleStreamHalfClose(uint32_t streamId) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) return;

        it->second->clientFinished = true;
        boost::system::error_code ec;
        if (!it->second->isUdp && it->second->isConnected) {
            it->second->targetSocket.shutdown(tcp::socket::shutdown_send, ec);
        }

        if ((it->second->targetFinished || it->second->isUdp) && it->second->writeQueue.empty() && !it->second->isWriting) {
            CloseStream(streamId);
        }
    }

    void TargetStreamManager::HandleStreamClose(uint32_t streamId) {
        CloseStream(streamId, false);
    }

    void TargetStreamManager::CloseStream(uint32_t streamId, bool notifyRemote) {
        auto it = m_streams.find(streamId);
        if (it != m_streams.end()) {
            boost::system::error_code ec;
            it->second->udpIdleTimer.cancel(ec);

            if (it->second->targetSocket.is_open()) {
                it->second->targetSocket.close(ec);
            }
            if (it->second->isUdp && it->second->udpSocket.is_open()) {
                it->second->udpSocket.close(ec);
            }

            if (notifyRemote) {
                m_sendFn(streamId, Protocol::Command::StreamClose, {}, it->second->isInteractive);
            }
            m_streams.erase(it);
        }
    }

    void TargetStreamManager::CloseAll() {
        boost::system::error_code ec;
        for (auto& [id, stream] : m_streams) {
            stream->udpIdleTimer.cancel(ec);
            if (stream->targetSocket.is_open()) stream->targetSocket.close(ec);
            if (stream->isUdp && stream->udpSocket.is_open()) stream->udpSocket.close(ec);
        }
        m_streams.clear();
    }

} // namespace Vpn::Server