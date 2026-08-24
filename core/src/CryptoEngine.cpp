#include "CryptoEngine.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace Vpn {

    void EvpPkeyDeleter::operator()(EVP_PKEY* pkey) const {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }

    void EvpCipherCtxDeleter::operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    bool CryptoEngine::GenerateKeyPair() {
        EVP_PKEY* rawKey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        if (!rawKey) {
            return false;
        }

        LocalKeyPair.reset(rawKey);
        return true;
    }

    CryptoEngine::CryptoEngine() {
        if (!GenerateKeyPair()) {
            throw std::runtime_error("CryptoEngine: Failed to generate X25519 keypair");
        }
    }

    std::vector<uint8_t> CryptoEngine::GetLocalPublicKey() const {
        if (!LocalKeyPair) return {};

        size_t len = 0;
        if (EVP_PKEY_get_raw_public_key(LocalKeyPair.get(), nullptr, &len) != 1) {
            return {};
        }

        std::vector<uint8_t> pubKey(len);
        if (EVP_PKEY_get_raw_public_key(LocalKeyPair.get(), pubKey.data(), &len) != 1) {
            return {};
        }

        return pubKey;
    }

    std::vector<uint8_t> CryptoEngine::DeriveSharedSecret(const std::vector<uint8_t>& peerPublicKey) {
        // X25519 публичный ключ должен быть ровно 32 байта
        if (!LocalKeyPair || peerPublicKey.size() != 32) {
            return {};
        }

        EVP_PKEY* peerKey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            nullptr,
            peerPublicKey.data(),
            peerPublicKey.size()
        );

        if (!peerKey) {
            return {};
        }

        EvpPkeyPtr peerKeyPtr(peerKey);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(LocalKeyPair.get(), nullptr);
        if (!ctx) return {};

        std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctxPtr(ctx, EVP_PKEY_CTX_free);

        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, peerKeyPtr.get()) <= 0) {
            return {};
        }

        size_t secretLen = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) {
            return {};
        }

        std::vector<uint8_t> sharedSecret(secretLen);
        if (EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen) <= 0) {
            return {};
        }

        return sharedSecret;
    }

    std::vector<uint8_t> CryptoEngine::GenerateRandomBytes(size_t Size) {
        if (Size == 0) return {};

        std::vector<uint8_t> buffer(Size);
        if (RAND_bytes(buffer.data(), static_cast<int>(Size)) != 1) {
            return {};
        }

        return buffer;
    }

    bool CryptoEngine::EncryptPayload(
        const std::vector<uint8_t>& PlainText,
        const std::vector<uint8_t>& SessionKey,
        const std::vector<uint8_t>& IvNonce,
        std::vector<uint8_t>& OutCipherText,
        std::vector<uint8_t>& OutAuthTag
    ) {
        if (SessionKey.size() != 32 || IvNonce.empty()) {
            return false;
        }

        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) return false;

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IvNonce.size()), nullptr) != 1) {
            return false;
        }

        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, SessionKey.data(), IvNonce.data()) != 1) {
            return false;
        }

        OutCipherText.resize(PlainText.size());
        int outLen = 0;

        if (!PlainText.empty()) {
            if (EVP_EncryptUpdate(ctx.get(), OutCipherText.data(), &outLen, PlainText.data(), static_cast<int>(PlainText.size())) != 1) {
                OutCipherText.clear();
                return false;
            }
        }

        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), OutCipherText.data() + outLen, &finalLen) != 1) {
            OutCipherText.clear();
            return false;
        }

        OutCipherText.resize(outLen + finalLen);

        OutAuthTag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, OutAuthTag.data()) != 1) {
            OutCipherText.clear();
            OutAuthTag.clear();
            return false;
        }

        return true;
    }

    bool CryptoEngine::DecryptPayload(
        const std::vector<uint8_t>& CipherText,
        const std::vector<uint8_t>& SessionKey,
        const std::vector<uint8_t>& IvNonce,
        const std::vector<uint8_t>& AuthTag,
        std::vector<uint8_t>& OutPlainText
    ) {
        if (SessionKey.size() != 32 || IvNonce.empty() || AuthTag.size() != 16) {
            return false;
        }

        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx) return false;

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            return false;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IvNonce.size()), nullptr) != 1) {
            return false;
        }

        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, SessionKey.data(), IvNonce.data()) != 1) {
            return false;
        }

        OutPlainText.resize(CipherText.size());
        int outLen = 0;

        if (!CipherText.empty()) {
            if (EVP_DecryptUpdate(ctx.get(), OutPlainText.data(), &outLen, CipherText.data(), static_cast<int>(CipherText.size())) != 1) {
                OutPlainText.clear();
                return false;
            }
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(AuthTag.size()), const_cast<uint8_t*>(AuthTag.data())) != 1) {
            OutPlainText.clear();
            return false;
        }

        int finalLen = 0;
        int ret = EVP_DecryptFinal_ex(ctx.get(), OutPlainText.data() + outLen, &finalLen);

        if (ret <= 0) {
            OutPlainText.clear();
            return false;
        }

        OutPlainText.resize(outLen + finalLen);
        return true;
    }

    // Новый конструктор: инициализация из сырого массива байтов
    CryptoEngine::CryptoEngine(const std::vector<uint8_t>& privateKey) {
        if (privateKey.size() != 32) {
            throw std::invalid_argument("CryptoEngine: Private key must be exactly 32 bytes for X25519");
        }

        EVP_PKEY* rawKey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519,
            nullptr,
            privateKey.data(),
            privateKey.size()
        );

        if (!rawKey) {
            throw std::runtime_error("CryptoEngine: Failed to import X25519 private key");
        }

        LocalKeyPair.reset(rawKey);
    }

    // Извлечение сырых байтов приватного ключа (аналогично GetLocalPublicKey)
    std::vector<uint8_t> CryptoEngine::GetLocalPrivateKey() const {
        if (!LocalKeyPair) return {};

        size_t len = 0;
        if (EVP_PKEY_get_raw_private_key(LocalKeyPair.get(), nullptr, &len) != 1) {
            return {};
        }

        std::vector<uint8_t> privKey(len);
        if (EVP_PKEY_get_raw_private_key(LocalKeyPair.get(), privKey.data(), &len) != 1) {
            return {};
        }

        return privKey;
    }

    std::string CryptoEngine::Base64Encode(const std::vector<uint8_t>& data) {
        if (data.empty()) return "";

        size_t outputLen = 4 * ((data.size() + 2) / 3);
        std::string encoded(outputLen, '\0');

        int encodedLen = EVP_EncodeBlock(
            reinterpret_cast<unsigned char*>(&encoded[0]),
            data.data(),
            static_cast<int>(data.size())
        );

        encoded.resize(static_cast<size_t>(encodedLen));
        return encoded;
    }

    std::vector<uint8_t> CryptoEngine::Base64Decode(const std::string& input) {
        if (input.empty()) return {};

        size_t maxDecodedLen = 3 * ((input.size() + 3) / 4);
        std::vector<uint8_t> decoded(maxDecodedLen);

        int decodedLen = EVP_DecodeBlock(
            decoded.data(),
            reinterpret_cast<const unsigned char*>(input.data()),
            static_cast<int>(input.size())
        );

        if (decodedLen < 0) return {};

        // Учитываем паддинг ('='), так как EVP_DecodeBlock возвращает длину без учета '='
        size_t padding = 0;
        if (input.size() >= 1 && input[input.size() - 1] == '=') padding++;
        if (input.size() >= 2 && input[input.size() - 2] == '=') padding++;

        decoded.resize(static_cast<size_t>(decodedLen) - padding);
        return decoded;
    }

} // namespace Vpn