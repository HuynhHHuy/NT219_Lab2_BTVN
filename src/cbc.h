#pragma once

#include <cstdint>
#include <vector>
#include "aes.h"

// PKCS#7 padding / unpadding
std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t> &data,
                              std::size_t blockSize = AES128::BlockSize);

std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t> &data,
                                std::size_t blockSize = AES128::BlockSize);

// CBC encryption/decryption với AES-128 + PKCS#7
std::vector<uint8_t> cbcEncrypt(const std::vector<uint8_t> &plaintext,
                                const uint8_t key[16],
                                const uint8_t iv[16]);

std::vector<uint8_t> cbcDecrypt(const std::vector<uint8_t> &ciphertext,
                                const uint8_t key[16],
                                const uint8_t iv[16]);

// CBC encryption/decryption KHÔNG padding (no-pad)
// - plaintext/ciphertext MUST có kích thước bội số 16
std::vector<uint8_t> cbcEncryptNoPad(const std::vector<uint8_t> &plaintext,
                                     const uint8_t key[16],
                                     const uint8_t iv[16]);

std::vector<uint8_t> cbcDecryptNoPad(const std::vector<uint8_t> &ciphertext,
                                     const uint8_t key[16],
                                     const uint8_t iv[16]);
