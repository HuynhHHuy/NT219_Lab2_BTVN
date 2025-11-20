#include "cbc.h"
#include <stdexcept>

// XOR 2 block 16 byte
static void xorBlock(uint8_t *dst, const uint8_t *src)
{
    for (int i = 0; i < 16; ++i)
    {
        dst[i] ^= src[i];
    }
}

std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t> &data,
                              std::size_t blockSize)
{
    if (blockSize == 0 || blockSize > 255)
    {
        throw std::runtime_error("Invalid blockSize");
    }

    std::vector<uint8_t> out = data;
    std::size_t padLen = blockSize - (out.size() % blockSize);
    if (padLen == 0)
        padLen = blockSize;

    out.insert(out.end(), padLen, static_cast<uint8_t>(padLen));
    return out;
}

std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t> &data,
                                std::size_t blockSize)
{
    if (data.empty() || data.size() % blockSize != 0)
    {
        throw std::runtime_error("Invalid PKCS#7 padding (size)");
    }
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > blockSize)
    {
        throw std::runtime_error("Invalid PKCS#7 padding (value)");
    }
    if (padLen > data.size())
    {
        throw std::runtime_error("Invalid PKCS#7 padding (too large)");
    }

    // kiểm tra tất cả pad byte
    for (std::size_t i = 0; i < padLen; ++i)
    {
        if (data[data.size() - 1 - i] != padLen)
        {
            throw std::runtime_error("Invalid PKCS#7 padding (pattern)");
        }
    }

    std::vector<uint8_t> out(data.begin(), data.end() - padLen);
    return out;
}

// ===== CBC + PKCS#7 =====

std::vector<uint8_t> cbcEncrypt(const std::vector<uint8_t> &plaintext,
                                const uint8_t key[16],
                                const uint8_t iv[16])
{
    AES128 aes(key);

    // pad plaintext
    std::vector<uint8_t> padded = pkcs7Pad(plaintext, AES128::BlockSize);

    std::vector<uint8_t> out;
    out.resize(padded.size());

    uint8_t prev[16];
    for (int i = 0; i < 16; ++i)
        prev[i] = iv[i];

    uint8_t block[16];
    uint8_t cipher[16];

    for (std::size_t offset = 0; offset < padded.size(); offset += 16)
    {
        // copy block
        for (int i = 0; i < 16; ++i)
        {
            block[i] = padded[offset + i];
        }

        // XOR với prev (IV hoặc ciphertext trước)
        xorBlock(block, prev);

        // AES encrypt
        aes.encryptBlock(block, cipher);

        // lưu output và cập nhật prev
        for (int i = 0; i < 16; ++i)
        {
            out[offset + i] = cipher[i];
            prev[i] = cipher[i];
        }
    }

    return out;
}

std::vector<uint8_t> cbcDecrypt(const std::vector<uint8_t> &ciphertext,
                                const uint8_t key[16],
                                const uint8_t iv[16])
{
    if (ciphertext.empty() || ciphertext.size() % 16 != 0)
    {
        throw std::runtime_error("Ciphertext size must be multiple of 16");
    }

    AES128 aes(key);

    std::vector<uint8_t> plain;
    plain.resize(ciphertext.size());

    uint8_t prev[16];
    for (int i = 0; i < 16; ++i)
        prev[i] = iv[i];

    uint8_t block[16];
    uint8_t decrypted[16];

    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16)
    {
        // copy current ciphertext block
        for (int i = 0; i < 16; ++i)
        {
            block[i] = ciphertext[offset + i];
        }

        // AES decrypt
        aes.decryptBlock(block, decrypted);

        // XOR với prev để ra plaintext block
        for (int i = 0; i < 16; ++i)
        {
            plain[offset + i] = decrypted[i] ^ prev[i];
        }

        // cập nhật prev
        for (int i = 0; i < 16; ++i)
        {
            prev[i] = block[i];
        }
    }

    // remove padding
    return pkcs7Unpad(plain, AES128::BlockSize);
}

// ===== CBC no-pad (dùng cho KAT SP 800-38A) =====

std::vector<uint8_t> cbcEncryptNoPad(const std::vector<uint8_t> &plaintext,
                                     const uint8_t key[16],
                                     const uint8_t iv[16])
{
    if (plaintext.empty() || (plaintext.size() % 16) != 0)
    {
        throw std::runtime_error("Plaintext size must be multiple of 16 for no-pad CBC");
    }

    AES128 aes(key);

    std::vector<uint8_t> out;
    out.resize(plaintext.size());

    uint8_t prev[16];
    for (int i = 0; i < 16; ++i)
        prev[i] = iv[i];

    uint8_t block[16];
    uint8_t cipher[16];

    for (std::size_t offset = 0; offset < plaintext.size(); offset += 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            block[i] = plaintext[offset + i];
        }

        xorBlock(block, prev);

        aes.encryptBlock(block, cipher);

        for (int i = 0; i < 16; ++i)
        {
            out[offset + i] = cipher[i];
            prev[i] = cipher[i];
        }
    }

    return out;
}

std::vector<uint8_t> cbcDecryptNoPad(const std::vector<uint8_t> &ciphertext,
                                     const uint8_t key[16],
                                     const uint8_t iv[16])
{
    if (ciphertext.empty() || (ciphertext.size() % 16) != 0)
    {
        throw std::runtime_error("Ciphertext size must be multiple of 16 for no-pad CBC");
    }

    AES128 aes(key);

    std::vector<uint8_t> plain;
    plain.resize(ciphertext.size());

    uint8_t prev[16];
    for (int i = 0; i < 16; ++i)
        prev[i] = iv[i];

    uint8_t block[16];
    uint8_t decrypted[16];

    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            block[i] = ciphertext[offset + i];
        }

        aes.decryptBlock(block, decrypted);

        for (int i = 0; i < 16; ++i)
        {
            plain[offset + i] = decrypted[i] ^ prev[i];
        }

        for (int i = 0; i < 16; ++i)
        {
            prev[i] = block[i];
        }
    }

    return plain; // KHÔNG unpad
}
