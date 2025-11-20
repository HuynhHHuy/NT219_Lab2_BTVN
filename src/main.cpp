#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype>
#include <stdexcept>

#include "cbc.h"

// ========== I/O tiện ích ==========

std::vector<uint8_t> readFileBinary(const std::string &path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs)
    {
        throw std::runtime_error("Cannot open input file: " + path);
    }
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    return data;
}

void writeFileBinary(const std::string &path, const std::vector<uint8_t> &data)
{
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs)
    {
        throw std::runtime_error("Cannot open output file: " + path);
    }
    ofs.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
}

// ========== xử lý hex ==========

uint8_t hexToByte(char hi, char lo)
{
    auto hexVal = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        return -1;
    };
    int h = hexVal(hi);
    int l = hexVal(lo);
    if (h < 0 || l < 0)
    {
        throw std::runtime_error("Invalid hex digit");
    }
    return static_cast<uint8_t>((h << 4) | l);
}

// Parse chuỗi hex 32 ký tự -> 16 byte (key/iv)
void parseHexKeyOrIv(const std::string &hex, uint8_t out[16])
{
    if (hex.size() != 32)
    {
        throw std::runtime_error("Hex string must be 32 characters (16 bytes)");
    }
    for (int i = 0; i < 16; ++i)
    {
        out[i] = hexToByte(hex[2 * i], hex[2 * i + 1]);
    }
}

// Parse chuỗi hex bất kỳ (length chẵn) -> vector<uint8_t>
std::vector<uint8_t> hexToBytes(const std::string &hex)
{
    if (hex.size() % 2 != 0)
    {
        throw std::runtime_error("Hex string length must be even");
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        out.push_back(hexToByte(hex[i], hex[i + 1]));
    }
    return out;
}

// So sánh 2 mảng byte
bool bytesEqual(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

// In usage
void printUsage()
{
    std::cout
        << "Usage:\n"
        << "  aes_tool enc --in <input> --out <output> --key-hex <32 hex> --iv-hex <32 hex> [--no-pad]\n"
        << "  aes_tool dec --in <input> --out <output> --key-hex <32 hex> --iv-hex <32 hex> [--no-pad]\n"
        << "  aes_tool selftest\n"
        << "\nExamples:\n"
        << "  aes_tool enc --in plain.bin --out cipher.bin \\\n"
        << "      --key-hex 00112233445566778899aabbccddeeff \\\n"
        << "      --iv-hex  000102030405060708090a0b0c0d0e0f\n"
        << "\n  aes_tool selftest   # run FIPS-197 + SP800-38A KATs\n";
}

// ========== SELFTESTS ==========

// FIPS-197 AES-128 ECB test vector (Appendix C.1)
bool selftest_fips197()
{
    std::string keyHex =
        "000102030405060708090A0B0C0D0E0F";
    std::string ptHex =
        "00112233445566778899AABBCCDDEEFF";
    std::string ctExpectedHex =
        "69C4E0D86A7B0430D8CDB78070B4C55A";

    auto keyBytes = hexToBytes(keyHex);
    auto ptBytes = hexToBytes(ptHex);
    auto ctExpected = hexToBytes(ctExpectedHex);

    uint8_t key[16];
    std::copy(keyBytes.begin(), keyBytes.end(), key);

    AES128 aes(key);

    uint8_t out[16];
    aes.encryptBlock(ptBytes.data(), out);

    std::vector<uint8_t> ct(out, out + 16);

    if (!bytesEqual(ct, ctExpected))
    {
        std::cerr << "[FIPS-197] Encrypt mismatch!\n";
        return false;
    }

    // test decrypt
    uint8_t dec[16];
    aes.decryptBlock(ctExpected.data(), dec);
    std::vector<uint8_t> decVec(dec, dec + 16);
    if (!bytesEqual(decVec, ptBytes))
    {
        std::cerr << "[FIPS-197] Decrypt mismatch!\n";
        return false;
    }

    std::cout << "[FIPS-197] AES-128 ECB test: OK\n";
    return true;
}

// SP 800-38A F.2.1 CBC-AES128.Encrypt (no padding)
bool selftest_sp800_38a_cbc()
{
    std::string keyHex =
        "2B7E151628AED2A6ABF7158809CF4F3C";
    std::string ivHex =
        "000102030405060708090A0B0C0D0E0F";

    std::string ptHex =
        "6BC1BEE22E409F96E93D7E117393172A"
        "AE2D8A571E03AC9C9EB76FAC45AF8E51"
        "30C81C46A35CE411E5FBC1191A0A52EF"
        "F69F2445DF4F9B17AD2B417BE66C3710";

    std::string ctExpectedHex =
        "7649ABAC8119B246CEE98E9B12E9197D"
        "5086CB9B507219EE95DB113A917678B2"
        "73BED6B8E3C1743B7116E69E22229516"
        "3FF1CAA1681FAC09120ECA307586E1A7";

    auto keyBytes = hexToBytes(keyHex);
    auto ivBytes = hexToBytes(ivHex);
    auto ptBytes = hexToBytes(ptHex);
    auto ctExpected = hexToBytes(ctExpectedHex);

    uint8_t key[16];
    uint8_t iv[16];
    std::copy(keyBytes.begin(), keyBytes.end(), key);
    std::copy(ivBytes.begin(), ivBytes.end(), iv);

    // Encrypt no-pad
    auto ct = cbcEncryptNoPad(ptBytes, key, iv);
    if (!bytesEqual(ct, ctExpected))
    {
        std::cerr << "[SP800-38A] CBC Encrypt mismatch!\n";
        return false;
    }

    // Decrypt no-pad
    auto pt = cbcDecryptNoPad(ctExpected, key, iv);
    if (!bytesEqual(pt, ptBytes))
    {
        std::cerr << "[SP800-38A] CBC Decrypt mismatch!\n";
        return false;
    }

    std::cout << "[SP800-38A] CBC-AES128 test: OK\n";
    return true;
}

bool runSelfTests()
{
    bool ok1 = selftest_fips197();
    bool ok2 = selftest_sp800_38a_cbc();

    if (ok1 && ok2)
    {
        std::cout << "All self-tests PASSED.\n";
        return true;
    }
    else
    {
        std::cout << "Self-tests FAILED.\n";
        return false;
    }
}

// ========== main ==========

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::string mode = argv[1]; // "enc" / "dec" / "selftest"

    if (mode == "selftest")
    {
        try
        {
            bool ok = runSelfTests();
            return ok ? 0 : 1;
        }
        catch (const std::exception &ex)
        {
            std::cerr << "Selftest error: " << ex.what() << "\n";
            return 1;
        }
    }

    // Các mode còn lại: enc / dec
    std::string inPath;
    std::string outPath;
    std::string keyHex;
    std::string ivHex;
    bool noPad = false;

    for (int i = 2; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--in" && i + 1 < argc)
        {
            inPath = argv[++i];
        }
        else if (arg == "--out" && i + 1 < argc)
        {
            outPath = argv[++i];
        }
        else if (arg == "--key-hex" && i + 1 < argc)
        {
            keyHex = argv[++i];
        }
        else if (arg == "--iv-hex" && i + 1 < argc)
        {
            ivHex = argv[++i];
        }
        else if (arg == "--no-pad")
        {
            noPad = true;
        }
        else
        {
            std::cerr << "Unknown or incomplete option: " << arg << "\n";
            printUsage();
            return 1;
        }
    }

    if ((mode != "enc" && mode != "dec") ||
        inPath.empty() || outPath.empty() || keyHex.empty() || ivHex.empty())
    {
        std::cerr << "Missing or invalid arguments.\n";
        printUsage();
        return 1;
    }

    try
    {
        uint8_t key[16];
        uint8_t iv[16];
        parseHexKeyOrIv(keyHex, key);
        parseHexKeyOrIv(ivHex, iv);

        std::vector<uint8_t> input = readFileBinary(inPath);
        std::vector<uint8_t> output;

        if (mode == "enc")
        {
            if (noPad)
            {
                if (input.size() % 16 != 0)
                {
                    throw std::runtime_error("Input size must be multiple of 16 when using --no-pad");
                }
                output = cbcEncryptNoPad(input, key, iv);
            }
            else
            {
                output = cbcEncrypt(input, key, iv);
            }
        }
        else
        { // dec
            if (noPad)
            {
                if (input.size() % 16 != 0)
                {
                    throw std::runtime_error("Ciphertext size must be multiple of 16 when using --no-pad");
                }
                output = cbcDecryptNoPad(input, key, iv);
            }
            else
            {
                output = cbcDecrypt(input, key, iv);
            }
        }

        writeFileBinary(outPath, output);

        std::cout << "Done (" << mode << (noPad ? ", no-pad" : "") << "). Output written to: " << outPath << "\n";
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}

// ./aes_tool.exe enc --in plain.txt --out cipher.bin --key-hex 00112233445566778899aabbccddeeff --iv-hex 000102030405060708090a0b0c0d0e0f
// ./aes_tool.exe dec --in cipher.bin --out plain2.txt --key-hex 00112233445566778899aabbccddeeff --iv-hex 000102030405060708090a0b0c0d0e0f