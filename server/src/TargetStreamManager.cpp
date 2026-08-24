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

    void TargetStreamManager::HandleStreamOpen(uint32_t streamId, const std::vector<uint8_t>& payload) {
        Protocol::TargetAddress target;
        if (!Protocol::StreamFrameHelper::DeserializeTargetAddress(payload.data(), payload.size(), target)) {
            m_sendFn(streamId, Protocol::Command::StreamClose, {}); return;
        }

        std::cout << "[Server] Mux Stream #" << streamId << " requesting connection to " << target.address << ":" << target.port << "\n";
        auto stream = std::make_shared<RemoteStream>(streamId, m_executor);
        m_streams[streamId] = stream;

        auto self = shared_from_this();
        auto onConnected = [this, self, streamId, stream](boost::system::error_code ec) {
            if (ec) { CloseStream(streamId); return; }
            std::cout << "[Server] Stream #" << streamId << " connected to target successfully!\n";
            m_sendFn(streamId, Protocol::Command::StreamOpen, { 0x00 });
            DoReadFromTarget(stream);
            };

        if (target.type == Protocol::AddressType::IPv4) {
            boost::system::error_code ec;
            auto ipAddr = boost::asio::ip::make_address_v4(target.address, ec);
            if (ec) { CloseStream(streamId); return; }
            stream->targetSocket.async_connect(tcp::endpoint(ipAddr, target.port), onConnected);
        }
        else {
            auto resolver = std::make_shared<tcp::resolver>(m_executor);
            resolver->async_resolve(target.address, std::to_string(target.port),
                [this, self, stream, resolver, onConnected](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                    if (ec) { CloseStream(stream->streamId); return; }
                    boost::asio::async_connect(stream->targetSocket, endpoints,
                        [onConnected](boost::system::error_code connectEc, const tcp::endpoint&) { onConnected(connectEc); });
                });
        }
    }

    void TargetStreamManager::HandleStreamData(uint32_t streamId, const std::vector<uint8_t>& payload) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) return;

        it->second->writeQueue.push_back(std::make_shared<std::vector<uint8_t>>(payload));
        if (!it->second->isWriting) DoWriteToTarget(it->second);
    }

    void TargetStreamManager::DoWriteToTarget(std::shared_ptr<RemoteStream> stream) {
        if (stream->writeQueue.empty()) { stream->isWriting = false; return; }

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
                        m_sendFn(stream->streamId, Protocol::Command::StreamHalfClose, {});
                        if (stream->clientFinished) CloseStream(stream->streamId);
                        return;
                    }
                    CloseStream(stream->streamId);
                    return;
                }
                std::vector<uint8_t> payload(stream->readBuffer.begin(), stream->readBuffer.begin() + bytesTransferred);
                m_sendFn(stream->streamId, Protocol::Command::StreamData, payload);
                DoReadFromTarget(stream);
            });
    }

    void TargetStreamManager::HandleStreamHalfClose(uint32_t streamId) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) return;

        it->second->clientFinished = true;
        boost::system::error_code ec;
        it->second->targetSocket.shutdown(tcp::socket::shutdown_send, ec);

        std::cout << "[Server] Stream #" << streamId << " HalfClose received. Target shutdown_send: " << (ec ? ec.message() : "OK") << "\n";
        if (it->second->targetFinished) CloseStream(streamId);
    }

    void TargetStreamManager::HandleStreamClose(uint32_t streamId) {
        std::cout << "[Server] Closed Mux Stream #" << streamId << "\n";
        CloseStream(streamId);
    }

    void TargetStreamManager::CloseStream(uint32_t streamId) {
        auto it = m_streams.find(streamId);
        if (it != m_streams.end()) {
            boost::system::error_code ec;
            it->second->targetSocket.close(ec);
            m_sendFn(streamId, Protocol::Command::StreamClose, {});
            m_streams.erase(it);
        }
    }

    void TargetStreamManager::CloseAll() {
        boost::system::error_code ec;
        for (auto& [id, stream] : m_streams) {
            stream->targetSocket.close(ec);
        }
        m_streams.clear();
    }

} // namespace Vpn::Server