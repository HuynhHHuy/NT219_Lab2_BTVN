#include "aes.h"
#include <cstring> // memcpy

// S-box chuẩn AES
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// inverse S-box
static uint8_t inv_sbox[256];

// Rcon (chỉ dùng 1..10)
static const uint8_t Rcon[11] = {
    0x00,
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36};

// Khởi tạo inv_sbox (chỉ chạy 1 lần)
static bool init_inv_sbox()
{
    for (int i = 0; i < 256; ++i)
    {
        inv_sbox[sbox[i]] = static_cast<uint8_t>(i);
    }
    return true;
}
static bool inv_sbox_initialized = init_inv_sbox();

// Truy cập state: dùng layout column-major
// state[4*c + r] với r,c ∈ {0..3}

static void AddRoundKey(uint8_t state[16], const uint8_t roundKeys[176], int round)
{
    const uint8_t *rk = roundKeys + round * 16;
    for (int i = 0; i < 16; ++i)
    {
        state[i] ^= rk[i];
    }
}

static void SubBytes(uint8_t state[16])
{
    for (int i = 0; i < 16; ++i)
    {
        state[i] = sbox[state[i]];
    }
}

static void InvSubBytes(uint8_t state[16])
{
    for (int i = 0; i < 16; ++i)
    {
        state[i] = inv_sbox[state[i]];
    }
}

static void ShiftRows(uint8_t state[16])
{
    auto get = [&](int r, int c) -> uint8_t &
    {
        return state[4 * c + r];
    };

    // row 1: shift left 1
    uint8_t row1[4];
    for (int c = 0; c < 4; ++c)
        row1[c] = get(1, c);
    uint8_t row1_rot[4] = {row1[1], row1[2], row1[3], row1[0]};
    for (int c = 0; c < 4; ++c)
        get(1, c) = row1_rot[c];

    // row 2: shift left 2
    uint8_t row2[4];
    for (int c = 0; c < 4; ++c)
        row2[c] = get(2, c);
    uint8_t row2_rot[4] = {row2[2], row2[3], row2[0], row2[1]};
    for (int c = 0; c < 4; ++c)
        get(2, c) = row2_rot[c];

    // row 3: shift left 3 (tức là right 1)
    uint8_t row3[4];
    for (int c = 0; c < 4; ++c)
        row3[c] = get(3, c);
    uint8_t row3_rot[4] = {row3[3], row3[0], row3[1], row3[2]};
    for (int c = 0; c < 4; ++c)
        get(3, c) = row3_rot[c];
}

static void InvShiftRows(uint8_t state[16])
{
    auto get = [&](int r, int c) -> uint8_t &
    {
        return state[4 * c + r];
    };

    // row 1: shift right 1
    uint8_t row1[4];
    for (int c = 0; c < 4; ++c)
        row1[c] = get(1, c);
    uint8_t row1_rot[4] = {row1[3], row1[0], row1[1], row1[2]};
    for (int c = 0; c < 4; ++c)
        get(1, c) = row1_rot[c];

    // row 2: shift right 2
    uint8_t row2[4];
    for (int c = 0; c < 4; ++c)
        row2[c] = get(2, c);
    uint8_t row2_rot[4] = {row2[2], row2[3], row2[0], row2[1]}; // left2 == right2
    for (int c = 0; c < 4; ++c)
        get(2, c) = row2_rot[c];

    // row 3: shift right 3 (tức left1)
    uint8_t row3[4];
    for (int c = 0; c < 4; ++c)
        row3[c] = get(3, c);
    uint8_t row3_rot[4] = {row3[1], row3[2], row3[3], row3[0]};
    for (int c = 0; c < 4; ++c)
        get(3, c) = row3_rot[c];
}

static uint8_t xtime(uint8_t a)
{
    uint16_t x = static_cast<uint16_t>(a) << 1;
    if (x & 0x100)
    {
        x ^= 0x11B;
    }
    return static_cast<uint8_t>(x & 0xFF);
}

static void MixColumns(uint8_t state[16])
{
    for (int c = 0; c < 4; ++c)
    {
        int idx = 4 * c;
        uint8_t a0 = state[idx + 0];
        uint8_t a1 = state[idx + 1];
        uint8_t a2 = state[idx + 2];
        uint8_t a3 = state[idx + 3];

        uint8_t t = a0 ^ a1 ^ a2 ^ a3;
        uint8_t u = a0;

        state[idx + 0] ^= t ^ xtime(a0 ^ a1);
        state[idx + 1] ^= t ^ xtime(a1 ^ a2);
        state[idx + 2] ^= t ^ xtime(a2 ^ a3);
        state[idx + 3] ^= t ^ xtime(a3 ^ u);
    }
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    for (int i = 0; i < 8; ++i)
    {
        if (b & 1)
        {
            res ^= a;
        }
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi)
        {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return res;
}

static void InvMixColumns(uint8_t state[16])
{
    for (int c = 0; c < 4; ++c)
    {
        int idx = 4 * c;
        uint8_t a0 = state[idx + 0];
        uint8_t a1 = state[idx + 1];
        uint8_t a2 = state[idx + 2];
        uint8_t a3 = state[idx + 3];

        uint8_t s0 = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        uint8_t s1 = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        uint8_t s2 = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        uint8_t s3 = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);

        state[idx + 0] = s0;
        state[idx + 1] = s1;
        state[idx + 2] = s2;
        state[idx + 3] = s3;
    }
}

// --- Key schedule helpers ---

static void RotWord(uint8_t w[4])
{
    uint8_t t = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = t;
}

static void SubWord(uint8_t w[4])
{
    for (int i = 0; i < 4; ++i)
    {
        w[i] = sbox[w[i]];
    }
}

// --- AES128 implementation ---

AES128::AES128(const uint8_t key[16])
{
    keyExpansion(key);
}

void AES128::keyExpansion(const uint8_t key[16])
{
    // AES-128: Nk=4, Nr=10, Nb=4, tổng 44 word = 176 byte
    uint8_t w[44][4];

    // 4 word đầu từ key
    for (int i = 0; i < 4; ++i)
    {
        w[i][0] = key[4 * i + 0];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }

    for (int i = 4; i < 44; ++i)
    {
        uint8_t temp[4];
        temp[0] = w[i - 1][0];
        temp[1] = w[i - 1][1];
        temp[2] = w[i - 1][2];
        temp[3] = w[i - 1][3];

        if (i % 4 == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / 4];
        }

        w[i][0] = w[i - 4][0] ^ temp[0];
        w[i][1] = w[i - 4][1] ^ temp[1];
        w[i][2] = w[i - 4][2] ^ temp[2];
        w[i][3] = w[i - 4][3] ^ temp[3];
    }

    // copy vào roundKeys (44 * 4 = 176 byte)
    int idx = 0;
    for (int i = 0; i < 44; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            roundKeys[idx++] = w[i][j];
        }
    }
}

void AES128::encryptBlock(const uint8_t in[16], uint8_t out[16]) const
{
    uint8_t state[16];
    std::memcpy(state, in, 16);

    // Round 0
    AddRoundKey(state, roundKeys, 0);

    // Rounds 1..9
    for (int round = 1; round <= 9; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys, round);
    }

    // Round 10
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys, 10);

    std::memcpy(out, state, 16);
}

void AES128::decryptBlock(const uint8_t in[16], uint8_t out[16]) const
{
    uint8_t state[16];
    std::memcpy(state, in, 16);

    // Round 10
    AddRoundKey(state, roundKeys, 10);

    // Rounds 9..1
    for (int round = 9; round >= 1; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys, round);
        InvMixColumns(state);
    }

    // Round 0
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys, 0);

    std::memcpy(out, state, 16);
}
