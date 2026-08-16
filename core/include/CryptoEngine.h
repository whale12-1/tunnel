#pragma once

#include <memory>
#include <vector>
#include <cstdint>
#include <cstddef>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace Vpn {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* pkey) const;
};

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const;
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine() = default;

    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    std::vector<uint8_t> GetLocalPublicKey() const;
    std::vector<uint8_t> DeriveSharedSecret(const std::vector<uint8_t>& peerPublicKey);

    // --- Реализуемые функции ---
    static std::vector<uint8_t> GenerateRandomBytes(size_t Size);

    bool EncryptPayload(
        const std::vector<uint8_t>& PlainText,
        const std::vector<uint8_t>& SessionKey,
        const std::vector<uint8_t>& IvNonce,
        std::vector<uint8_t>& OutCipherText,
        std::vector<uint8_t>& OutAuthTag
    );

    bool DecryptPayload(
        const std::vector<uint8_t>& CipherText,
        const std::vector<uint8_t>& SessionKey,
        const std::vector<uint8_t>& IvNonce,
        const std::vector<uint8_t>& AuthTag,
        std::vector<uint8_t>& OutPlainText
    );

private:
    bool GenerateKeyPair();
    EvpPkeyPtr LocalKeyPair{ nullptr };
};

} // namespace Vpn