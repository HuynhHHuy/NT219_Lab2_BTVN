#pragma once

#include <cstdint>
#include <cstddef>

// Triển khai AES-128 (16-byte key, 10 rounds)
class AES128
{
public:
    static constexpr std::size_t BlockSize = 16;

    // key: 16 byte
    AES128(const uint8_t key[16]);

    // Mã hoá 1 block (16 byte)
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;

    // Giải mã 1 block (16 byte)
    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const;

private:
    uint8_t roundKeys[176]; // 11 * 16

    void keyExpansion(const uint8_t key[16]);
};
