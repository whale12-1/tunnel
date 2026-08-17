#include "Session.h"
#include "TlsHelper.h"
#include <iostream>
#include <random>
#include <unordered_set>

static const std::unordered_set<std::string> ALLOWED_SNIS = {
        "dl.google.com", "cloud.google.com", "www.google.com"
};

namespace Vpn::Server {

    Session::Session(tcp::socket clientSocket, std::shared_ptr<CryptoEngine> cryptoEngine)
        : m_clientSocket(std::move(clientSocket)),
        m_fallbackSocket(m_clientSocket.get_executor()),
        m_cryptoEngine(cryptoEngine)
    {
    }

    void Session::Start() {
        DoReadHandshake();
    }

    void Session::DoReadHandshake() {
        auto self = shared_from_this();
        m_payloadBuffer.resize(5);

        boost::asio::async_read(
            m_clientSocket,
            boost::asio::buffer(m_payloadBuffer.data(), 5),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec || m_payloadBuffer[0] != 0x16) {
                    std::cerr << "[Server Error] Handshake header read failed: " << ec.message() << ", type: " << (int)m_payloadBuffer[0] << "\n";
                    CloseAll();
                    return;
                }

                uint16_t bodyLen = (static_cast<uint16_t>(m_payloadBuffer[3]) << 8) | m_payloadBuffer[4];
                if (bodyLen < 71 || bodyLen > Protocol::MAX_FRAME_SIZE) {
                    std::cerr << "[Server Error] Invalid handshake bodyLen: " << bodyLen << "\n";
                    CloseAll();
                    return;
                }

                DoReadTlsBody(bodyLen);
            }
        );
    }

    void Session::DoReadTlsBody(uint16_t bodyLen) {
        auto self = shared_from_this();
        auto fullTlsPacket = std::make_shared<std::vector<uint8_t>>();
        fullTlsPacket->insert(fullTlsPacket->end(), m_payloadBuffer.begin(), m_payloadBuffer.begin() + 5);
        fullTlsPacket->resize(5 + bodyLen);

        boost::asio::async_read(
            m_clientSocket,
            boost::asio::buffer(fullTlsPacket->data() + 5, bodyLen),
            [this, self, fullTlsPacket](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Server Error] Handshake body read failed: " << ec.message() << "\n";
                    CloseAll();
                    return;
                }

                std::vector<uint8_t> clientPubKey;
                std::string sniHost;
                auto localPubKey = m_cryptoEngine->GetLocalPublicKey();

                if (!Protocol::TlsHelper::VerifyAndParseClientHello(*fullTlsPacket, localPubKey, clientPubKey, sniHost)) {
                    std::cout << "[Server] Active probe or invalid HMAC. Fallback...\n";
                    DoFallbackToRealServer(fullTlsPacket);
                    return;
                }

                m_sessionKey = m_cryptoEngine->DeriveSharedSecret(clientPubKey);
                if (m_sessionKey.empty()) {
                    std::cerr << "[Server Error] Failed to derive shared secret.\n";
                    DoFallbackToRealServer(fullTlsPacket);
                    return;
                }

                std::cout << "[Server] Valid TLS ClientHello received (SNI: " << sniHost << "). Handshake success!\n";

                std::vector<uint8_t> clientSessionId(fullTlsPacket->begin() + 44, fullTlsPacket->begin() + 76);
                auto serverHelloPacket = Protocol::TlsHelper::BuildServerHello(localPubKey, clientSessionId);

                std::vector<uint8_t> ccs = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
                serverHelloPacket.insert(serverHelloPacket.end(), ccs.begin(), ccs.end());

                auto serverHelloBufPtr = std::make_shared<std::vector<uint8_t>>(std::move(serverHelloPacket));

                boost::asio::async_write(
                    m_clientSocket,
                    boost::asio::buffer(*serverHelloBufPtr),
                    [this, self, serverHelloBufPtr](boost::system::error_code writeEc, size_t) {
                        if (writeEc) {
                            std::cerr << "[Server Error] ServerHello write failed: " << writeEc.message() << "\n";
                            CloseAll();
                            return;
                        }
                        m_state = State::Tunneling;
                        std::cout << "[Server] Mux Tunnel Active! Sending Fake Certificate Payload...\n";

                        // --- ИМИТАЦИЯ TLS 1.3 СЕРТИФИКАТА GOOGLE ДЛЯ ОБХОДА DPI ---
                        // Генерируем мусорный пакет случайного размера (от 2500 до 3800 байт),
                        // который по размеру точно совпадает со стандартной цепочкой сертификатов Google.
                        static thread_local std::mt19937 rng(std::random_device{}());
                        std::uniform_int_distribution<size_t> dist(2500, 3800);
                        std::vector<uint8_t> dummyCertPayload(dist(rng), 0x00); // Заполняем нулями

                        // Отправляем как системный Ping. 
                        // Mux-протокол его зашифрует, добавит паддинг и обернет в TLS Record 0x17.
                        SendMuxFrame(Protocol::SYSTEM_STREAM_ID, Protocol::Command::Ping, dummyCertPayload);
                        // ----------------------------------------------------------

                        DoReadFrameHeader();
                    }
                );
            }
        );
    }

    void Session::DoReadFrameHeader() {
        auto self = shared_from_this();
        m_payloadBuffer.resize(5);

        boost::asio::async_read(
            m_clientSocket,
            boost::asio::buffer(m_payloadBuffer.data(), 5),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Server Error] Frame header read failed: " << ec.message() << "\n";
                    CloseAll();
                    return;
                }

                uint16_t payloadLen = (static_cast<uint16_t>(m_payloadBuffer[3]) << 8) | m_payloadBuffer[4];
                if (payloadLen == 0 || payloadLen > Protocol::MAX_FRAME_SIZE) {
                    std::cerr << "[Server Error] Invalid Mux frame payloadLen: " << payloadLen << "\n";
                    SendTlsAlertAndClose(0x14);
                    return;
                }

                if (m_payloadBuffer[0] == 0x14) {
                    auto skipBuf = std::make_shared<std::vector<uint8_t>>(payloadLen);
                    boost::asio::async_read(m_clientSocket, boost::asio::buffer(*skipBuf),
                        [this, self, skipBuf](boost::system::error_code skipEc, size_t) {
                            if (skipEc) { CloseAll(); return; }
                            DoReadFrameHeader();
                        });
                    return;
                }

                if (m_payloadBuffer[0] != 0x17) {
                    std::cerr << "[Server Error] Unexpected TLS record type: " << (int)m_payloadBuffer[0] << "\n";
                    SendTlsAlertAndClose(0x0A);
                    return;
                }

                DoReadFramePayload(payloadLen);
            }
        );
    }

    void Session::DoReadFramePayload(uint16_t payloadLen) {
        auto self = shared_from_this();
        m_payloadBuffer.resize(payloadLen);

        boost::asio::async_read(
            m_clientSocket,
            boost::asio::buffer(m_payloadBuffer.data(), payloadLen),
            [this, self](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Server Error] Frame payload read failed: " << ec.message() << "\n";
                    CloseAll();
                    return;
                }
                ProcessMuxFrame(m_payloadBuffer);
            }
        );
    }

    void Session::ProcessMuxFrame(const std::vector<uint8_t>& encryptedData) {
        if (encryptedData.size() <= Protocol::IV_SIZE + Protocol::TAG_SIZE) {
            std::cerr << "[Server Error] Encrypted data too small: " << encryptedData.size() << "\n";
            SendTlsAlertAndClose(0x14);
            return;
        }

        std::vector<uint8_t> iv(encryptedData.begin(), encryptedData.begin() + Protocol::IV_SIZE);
        std::vector<uint8_t> authTag(encryptedData.end() - Protocol::TAG_SIZE, encryptedData.end());
        std::vector<uint8_t> cipherText(encryptedData.begin() + Protocol::IV_SIZE, encryptedData.end() - Protocol::TAG_SIZE);

        std::vector<uint8_t> decryptedText;
        if (!m_cryptoEngine->DecryptPayload(cipherText, m_sessionKey, iv, authTag, decryptedText)) {
            std::cerr << "[Server Error] DecryptPayload failed!\n";
            SendTlsAlertAndClose(0x14);
            return;
        }

        std::vector<uint8_t> plainText;
        if (!Protocol::PaddingHelper::RemovePadding(decryptedText, plainText)) {
            std::cerr << "[Server Error] RemovePadding failed!\n";
            SendTlsAlertAndClose(0x14);
            return;
        }

        Protocol::MuxFrame frame;
        if (!Protocol::StreamFrameHelper::UnpackMuxFrame(plainText, frame)) {
            std::cerr << "[Server Error] UnpackMuxFrame failed!\n";
            SendTlsAlertAndClose(0x14);
            return;
        }

        switch (frame.command) {
        case Protocol::Command::Ping:
            SendMuxFrame(Protocol::SYSTEM_STREAM_ID, Protocol::Command::Pong, {});
            break;
        case Protocol::Command::StreamOpen:
            HandleStreamOpen(frame.streamId, frame.payload);
            break;
        case Protocol::Command::StreamData:
            HandleStreamData(frame.streamId, frame.payload);
            break;
        case Protocol::Command::StreamHalfClose:
            HandleStreamHalfClose(frame.streamId);
            break;
        case Protocol::Command::StreamClose:
            HandleStreamClose(frame.streamId);
            break;
        default:
            break;
        }

        DoReadFrameHeader();
    }

    void Session::HandleStreamOpen(uint32_t streamId, const std::vector<uint8_t>& payload) {
        Protocol::TargetAddress target;
        if (!Protocol::StreamFrameHelper::DeserializeTargetAddress(payload.data(), payload.size(), target)) {
            std::cerr << "[Server Error] Failed to deserialize target address for stream #" << streamId << "\n";
            SendMuxFrame(streamId, Protocol::Command::StreamClose, {});
            return;
        }

        std::cout << "[Server] Mux Stream #" << streamId << " requesting connection to "
            << target.address << ":" << target.port << "\n";

        auto stream = std::make_shared<RemoteStream>(streamId, m_clientSocket.get_executor());
        m_streams[streamId] = stream;

        auto self = shared_from_this();

        auto onConnected = [this, self, streamId, stream](boost::system::error_code ec) {
            if (ec) {
                std::cerr << "[Server Error] Stream #" << streamId << " target connect failed: " << ec.message() << "\n";
                CloseStream(streamId);
                return;
            }

            std::cout << "[Server] Stream #" << streamId << " connected to target successfully!\n";
            SendMuxFrame(streamId, Protocol::Command::StreamOpen, { 0x00 });
            DoReadFromTarget(stream);
            };

        if (target.type == Protocol::AddressType::IPv4) {
            boost::system::error_code ec;
            auto ipAddr = boost::asio::ip::make_address_v4(target.address, ec);
            if (ec) { CloseStream(streamId); return; }

            stream->targetSocket.async_connect(tcp::endpoint(ipAddr, target.port),
                [onConnected](boost::system::error_code connectEc) { onConnected(connectEc); });
        }
        else {
            auto resolver = std::make_shared<tcp::resolver>(m_clientSocket.get_executor());
            resolver->async_resolve(target.address, std::to_string(target.port),
                [this, self, stream, resolver, onConnected](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                    if (ec) { std::cerr << "[Server Error] Resolve failed: " << ec.message() << "\n"; CloseStream(stream->streamId); return; }
                    boost::asio::async_connect(stream->targetSocket, endpoints,
                        [onConnected](boost::system::error_code connectEc, const tcp::endpoint&) { onConnected(connectEc); });
                });
        }
    }

    void Session::HandleStreamData(uint32_t streamId, const std::vector<uint8_t>& payload) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) return;

        auto stream = it->second;

        // Безопасное хранение буфера
        stream->writeQueue.push_back(std::make_shared<std::vector<uint8_t>>(payload));
        if (!stream->isWriting) {
            DoWriteToTarget(stream);
        }
    }

    void Session::DoWriteToTarget(std::shared_ptr<RemoteStream> stream) {
        if (stream->writeQueue.empty()) {
            stream->isWriting = false;
            return;
        }

        stream->isWriting = true;
        auto self = shared_from_this();
        uint32_t streamId = stream->streamId;

        auto bufferPtr = stream->writeQueue.front(); // Удержание памяти

        boost::asio::async_write(
            stream->targetSocket,
            boost::asio::buffer(*bufferPtr),
            [this, self, stream, streamId, bufferPtr](boost::system::error_code ec, size_t bytesTransferred) {
                if (ec) {
                    std::cerr << "[Server Error] Write to target socket failed on stream #" << streamId
                        << ": " << ec.message() << "\n";
                    CloseStream(streamId);
                    return;
                }

                stream->writeQueue.pop_front();
                DoWriteToTarget(stream);
            }
        );
    }

    void Session::HandleStreamClose(uint32_t streamId) {
        std::cout << "[Server] Stream #" << streamId << " close requested by client.\n";
        CloseStream(streamId);
    }

    void Session::DoReadFromTarget(std::shared_ptr<RemoteStream> stream) {
        auto self = shared_from_this();
        uint32_t streamId = stream->streamId;

        stream->targetSocket.async_read_some(
            boost::asio::buffer(stream->readBuffer),
            [this, self, stream, streamId](boost::system::error_code ec, size_t bytesTransferred) {
                if (ec) {
                    if (ec == boost::asio::error::eof) {
                        if (!stream->targetFinished) {
                            stream->targetFinished = true;
                            SendMuxFrame(streamId, Protocol::Command::StreamHalfClose, {});

                            if (stream->clientFinished) {
                                CloseStream(streamId);
                            }
                        }
                        return;
                    }
                    CloseStream(streamId);
                    return;
                }

                std::vector<uint8_t> payload(stream->readBuffer.begin(), stream->readBuffer.begin() + bytesTransferred);
                SendMuxFrame(streamId, Protocol::Command::StreamData, payload);
                DoReadFromTarget(stream);
            }
        );
    }

    void Session::CloseStream(uint32_t streamId) {
        auto it = m_streams.find(streamId);
        if (it != m_streams.end()) {
            boost::system::error_code ec;
            it->second->targetSocket.close(ec);
            m_streams.erase(it);
            SendMuxFrame(streamId, Protocol::Command::StreamClose, {});
            std::cout << "[Server] Closed Mux Stream #" << streamId << "\n";
        }
    }

    void Session::SendMuxFrame(uint32_t streamId, Protocol::Command cmd, const std::vector<uint8_t>& payload) {
        size_t offset = 0;

        static thread_local std::mt19937 rng(std::random_device{}());
        // Можно варьировать диапазон в зависимости от нужд обфускации
        std::uniform_int_distribution<size_t> chunkDist(6000, 14500);

        // Фрагментация данных
        do {
            size_t currentChunkLimit = chunkDist(rng);
            size_t chunkSize = payload.empty() ? 0 : std::min(payload.size() - offset, currentChunkLimit);

            std::vector<uint8_t> chunk;
            if (chunkSize > 0) {
                chunk.assign(payload.begin() + offset, payload.begin() + offset + chunkSize);
            }

            auto plainMux = Protocol::StreamFrameHelper::PackMuxFrame(streamId, cmd, chunk);

            std::uniform_int_distribution<size_t> padDist(16, 128);
            auto padded = Protocol::PaddingHelper::AddPadding(plainMux, padDist(rng));
            auto iv = CryptoEngine::GenerateRandomBytes(Protocol::IV_SIZE);

            std::vector<uint8_t> cipherText, authTag;
            if (!m_cryptoEngine->EncryptPayload(padded, m_sessionKey, iv, cipherText, authTag)) return;

            auto tlsRecord = std::make_shared<std::vector<uint8_t>>();
            tlsRecord->push_back(0x17);
            tlsRecord->push_back(0x03); tlsRecord->push_back(0x03);
            uint16_t len = static_cast<uint16_t>(iv.size() + cipherText.size() + authTag.size());
            tlsRecord->push_back(len >> 8);
            tlsRecord->push_back(len & 0xFF);
            tlsRecord->insert(tlsRecord->end(), iv.begin(), iv.end());
            tlsRecord->insert(tlsRecord->end(), cipherText.begin(), cipherText.end());
            tlsRecord->insert(tlsRecord->end(), authTag.begin(), authTag.end());

            m_writeQueue.push_back(tlsRecord);
            if (!m_isWriting) {
                DoWriteQueue();
            }

            offset += chunkSize;
        } while (offset < payload.size());
    }

    void Session::DoWriteQueue() {
        if (m_writeQueue.empty()) {
            m_isWriting = false;
            return;
        }

        m_isWriting = true;
        auto self = shared_from_this();
        auto bufferPtr = m_writeQueue.front(); // Удержание памяти

        boost::asio::async_write(
            m_clientSocket,
            boost::asio::buffer(*bufferPtr),
            [this, self, bufferPtr](boost::system::error_code ec, size_t) {
                if (ec) {
                    std::cerr << "[Server Error] Write to client socket failed: " << ec.message() << "\n";
                    CloseAll();
                    return;
                }
                m_writeQueue.pop_front();
                DoWriteQueue();
            }
        );
    }

    void Session::CloseAll() {
        boost::system::error_code ec;
        if (m_clientSocket.is_open()) m_clientSocket.close(ec);
        if (m_fallbackSocket.is_open()) m_fallbackSocket.close(ec);

        for (auto& [id, stream] : m_streams) {
            stream->targetSocket.close(ec);
        }
        m_streams.clear();
    }

    void Session::SendTlsAlertAndClose(uint8_t alertDescription) {
        auto alertPacket = std::make_shared<std::vector<uint8_t>>(
            std::initializer_list<uint8_t>{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, alertDescription }
        );

        auto self = shared_from_this();
        boost::asio::async_write(
            m_clientSocket,
            boost::asio::buffer(*alertPacket),
            [this, self, alertPacket](boost::system::error_code, size_t) {
                CloseAll();
            }
        );
    }

    void Session::DoFallbackToRealServer(std::shared_ptr<std::vector<uint8_t>> initialPacket) {
        auto self = shared_from_this();
        std::string sniHost;
        bool parsed = Vpn::Protocol::TlsHelper::ParseSniFromClientHello(*initialPacket, sniHost);

        if (!parsed || ALLOWED_SNIS.find(sniHost) == ALLOWED_SNIS.end()) {
            sniHost = "dl.google.com";
        }

        auto resolver = std::make_shared<tcp::resolver>(m_clientSocket.get_executor());
        resolver->async_resolve(sniHost, "443",
            [this, self, initialPacket, resolver](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                if (ec) { CloseAll(); return; }

                boost::asio::async_connect(m_fallbackSocket, endpoints,
                    [this, self, initialPacket](boost::system::error_code connectEc, const tcp::endpoint&) {
                        if (connectEc) { CloseAll(); return; }

                        boost::asio::async_write(m_fallbackSocket, boost::asio::buffer(*initialPacket),
                            [this, self](boost::system::error_code writeEc, size_t) {
                                if (writeEc) { CloseAll(); return; }
                                StartRawRelaying();
                            });
                    });
            });
    }

    void Session::StartRawRelaying() {
        RelayClientToFallback();
        RelayFallbackToClient();
    }

    void Session::RelayClientToFallback() {
        auto self = shared_from_this();
        m_clientSocket.async_read_some(
            boost::asio::buffer(m_c2fBuffer),
            [this, self](boost::system::error_code ec, size_t length) {
                if (ec) { CloseAll(); return; }

                boost::asio::async_write(
                    m_fallbackSocket,
                    boost::asio::buffer(m_c2fBuffer.data(), length),
                    [this, self](boost::system::error_code writeEc, size_t) {
                        if (writeEc) { CloseAll(); return; }
                        RelayClientToFallback();
                    });
            });
    }

    void Session::RelayFallbackToClient() {
        auto self = shared_from_this();
        m_fallbackSocket.async_read_some(
            boost::asio::buffer(m_f2cBuffer),
            [this, self](boost::system::error_code ec, size_t length) {
                if (ec) { CloseAll(); return; }

                boost::asio::async_write(
                    m_clientSocket,
                    boost::asio::buffer(m_f2cBuffer.data(), length),
                    [this, self](boost::system::error_code writeEc, size_t) {
                        if (writeEc) { CloseAll(); return; }
                        RelayFallbackToClient();
                    });
            });
    }

    void Session::HandleStreamHalfClose(uint32_t streamId) {
        auto it = m_streams.find(streamId);
        if (it == m_streams.end()) return;

        auto stream = it->second;
        stream->clientFinished = true;

        boost::system::error_code ec;
        stream->targetSocket.shutdown(tcp::socket::shutdown_send, ec);

        std::cout << "[Server] Stream #" << streamId << " HalfClose received. Target shutdown_send: "
            << (ec ? ec.message() : "OK") << "\n";

        if (stream->targetFinished) {
            CloseStream(streamId);
        }
    }

} // namespace Vpn::Server