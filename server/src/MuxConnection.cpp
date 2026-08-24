#include "MuxConnection.h"
#include <iostream>
#include <random>

namespace Vpn::Server {

    MuxConnection::MuxConnection(tcp::socket socket, std::vector<uint8_t> sessionKey, std::shared_ptr<CryptoEngine> cryptoEngine)
        : m_socket(std::move(socket)),
        m_sessionKey(std::move(sessionKey)),
        m_cryptoEngine(std::move(cryptoEngine)) {
    }

    void MuxConnection::Start(FrameHandler onFrame, ErrorHandler onError) {
        m_onFrame = std::move(onFrame);
        m_onError = std::move(onError);
        DoReadFrameHeader();
    }

    void MuxConnection::DoReadFrameHeader() {
        auto self = shared_from_this();
        m_payloadBuffer.resize(5);

        boost::asio::async_read(m_socket, boost::asio::buffer(m_payloadBuffer.data(), 5),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec) { Close(); return; }

                uint16_t payloadLen = (static_cast<uint16_t>(m_payloadBuffer[3]) << 8) | m_payloadBuffer[4];
                if (payloadLen == 0 || payloadLen > Protocol::MAX_FRAME_SIZE) {
                    SendTlsAlertAndClose(0x14); return;
                }

                if (m_payloadBuffer[0] == 0x14) {
                    auto skipBuf = std::make_shared<std::vector<uint8_t>>(payloadLen);
                    boost::asio::async_read(m_socket, boost::asio::buffer(*skipBuf),
                        [this, self, skipBuf](boost::system::error_code skipEc, size_t) {
                            if (skipEc) { Close(); return; }
                            DoReadFrameHeader();
                        });
                    return;
                }

                if (m_payloadBuffer[0] != 0x17) {
                    SendTlsAlertAndClose(0x0A); return;
                }

                DoReadFramePayload(payloadLen);
            });
    }

    void MuxConnection::DoReadFramePayload(uint16_t payloadLen) {
        auto self = shared_from_this();
        m_payloadBuffer.resize(payloadLen);

        boost::asio::async_read(m_socket, boost::asio::buffer(m_payloadBuffer.data(), payloadLen),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec) { Close(); return; }
                ProcessMuxFrame(m_payloadBuffer);
            });
    }

    void MuxConnection::ProcessMuxFrame(const std::vector<uint8_t>& encryptedData) {
        if (encryptedData.size() <= Protocol::IV_SIZE + Protocol::TAG_SIZE) {
            SendTlsAlertAndClose(0x14); return;
        }

        std::vector<uint8_t> iv(encryptedData.begin(), encryptedData.begin() + Protocol::IV_SIZE);
        std::vector<uint8_t> authTag(encryptedData.end() - Protocol::TAG_SIZE, encryptedData.end());
        std::vector<uint8_t> cipherText(encryptedData.begin() + Protocol::IV_SIZE, encryptedData.end() - Protocol::TAG_SIZE);

        std::vector<uint8_t> decryptedText, plainText;
        if (!m_cryptoEngine->DecryptPayload(cipherText, m_sessionKey, iv, authTag, decryptedText) ||
            !Protocol::PaddingHelper::RemovePadding(decryptedText, plainText)) {
            SendTlsAlertAndClose(0x14); return;
        }

        Protocol::MuxFrame frame;
        if (!Protocol::StreamFrameHelper::UnpackMuxFrame(plainText, frame)) {
            SendTlsAlertAndClose(0x14); return;
        }

        if (frame.command == Protocol::Command::Ping) {
            SendMuxFrame(Protocol::SYSTEM_STREAM_ID, Protocol::Command::Pong, {});
        }
        else if (m_onFrame) {
            m_onFrame(frame);
        }

        DoReadFrameHeader();
    }

    void MuxConnection::SendMuxFrame(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload) {
        size_t offset = 0;
        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<size_t> chunkDist(6000, 14500);

        do {
            size_t currentChunkLimit = chunkDist(rng);
            size_t chunkSize = payload.empty() ? 0 : std::min(payload.size() - offset, currentChunkLimit);

            std::vector<uint8_t> chunk;
            if (chunkSize > 0) chunk.assign(payload.begin() + offset, payload.begin() + offset + chunkSize);

            auto plainMux = Protocol::StreamFrameHelper::PackMuxFrame(streamId, cmd, chunk);
            std::uniform_int_distribution<size_t> padDist(16, 128);
            auto padded = Protocol::PaddingHelper::AddPadding(plainMux, padDist(rng));
            auto iv = CryptoEngine::GenerateRandomBytes(Protocol::IV_SIZE);

            std::vector<uint8_t> cipherText, authTag;
            if (!m_cryptoEngine->EncryptPayload(padded, m_sessionKey, iv, cipherText, authTag)) return;

            auto tlsRecord = std::make_shared<std::vector<uint8_t>>();
            tlsRecord->push_back(0x17); tlsRecord->push_back(0x03); tlsRecord->push_back(0x03);
            uint16_t len = static_cast<uint16_t>(iv.size() + cipherText.size() + authTag.size());
            tlsRecord->push_back(len >> 8); tlsRecord->push_back(len & 0xFF);
            tlsRecord->insert(tlsRecord->end(), iv.begin(), iv.end());
            tlsRecord->insert(tlsRecord->end(), cipherText.begin(), cipherText.end());
            tlsRecord->insert(tlsRecord->end(), authTag.begin(), authTag.end());

            m_writeQueue.push_back(tlsRecord);
            if (!m_isWriting) DoWriteQueue();

            offset += chunkSize;
        } while (offset < payload.size());
    }

    void MuxConnection::DoWriteQueue() {
        if (m_writeQueue.empty()) {
            m_isWriting = false; return;
        }

        m_isWriting = true;
        auto self = shared_from_this();
        auto bufferPtr = m_writeQueue.front();

        boost::asio::async_write(m_socket, boost::asio::buffer(*bufferPtr),
            [this, self, bufferPtr](boost::system::error_code ec, size_t) {
                if (ec) { Close(); return; }
                m_writeQueue.pop_front();
                DoWriteQueue();
            });
    }

    void MuxConnection::SendTlsAlertAndClose(uint8_t alertDescription) {
        auto alertPacket = std::make_shared<std::vector<uint8_t>>(
            std::initializer_list<uint8_t>{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, alertDescription }
        );
        auto self = shared_from_this();
        boost::asio::async_write(m_socket, boost::asio::buffer(*alertPacket),
            [this, self, alertPacket](boost::system::error_code, size_t) { Close(); });
    }

    void MuxConnection::Close() {
        boost::system::error_code ec;
        if (m_socket.is_open()) m_socket.close(ec);
        if (m_onError) m_onError();
    }

} // namespace Vpn::Server