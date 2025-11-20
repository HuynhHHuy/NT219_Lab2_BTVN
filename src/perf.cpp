#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype>
#include <stdexcept>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <cmath>

#include "cbc.h"

// ==== I/O util ====

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

// ==== thống kê ====

struct Stats
{
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci_low_ms;
    double ci_high_ms;
};

Stats computeStats(const std::vector<double> &samples_ms)
{
    const std::size_t n = samples_ms.size();
    if (n == 0)
    {
        throw std::runtime_error("No samples to compute stats");
    }

    // mean
    double sum = std::accumulate(samples_ms.begin(), samples_ms.end(), 0.0);
    double mean = sum / static_cast<double>(n);

    // median
    std::vector<double> sorted = samples_ms;
    std::sort(sorted.begin(), sorted.end());
    double median;
    if (n % 2 == 0)
    {
        median = 0.5 * (sorted[n / 2 - 1] + sorted[n / 2]);
    }
    else
    {
        median = sorted[n / 2];
    }

    // sample stddev
    double sq_sum = 0.0;
    for (double x : samples_ms)
    {
        double diff = x - mean;
        sq_sum += diff * diff;
    }
    double stddev = std::sqrt(sq_sum / static_cast<double>(n - 1));

    // 95% CI: mean ± t * std/sqrt(n), với n=10 → t≈2.262
    double t_val = 2.262;
    double margin = t_val * stddev / std::sqrt(static_cast<double>(n));
    double ci_low = mean - margin;
    double ci_high = mean + margin;

    return Stats{mean, median, stddev, ci_low, ci_high};
}

// ==== cấu trúc lưu kết quả để xuất CSV ====

struct PerfResult
{
    std::string filename;
    std::size_t size_bytes;
    int rounds_per_block;
    int blocks;
    Stats stats;
    double throughput_MBps; // enc+dec
};

// ==== chạy perf 1 file ====

void runPerfForFile(const std::string &filename,
                    const uint8_t key[16],
                    const uint8_t iv[16],
                    int rounds_per_block,
                    int blocks,
                    PerfResult &outResult)
{
    using clock = std::chrono::high_resolution_clock;

    std::vector<uint8_t> data = readFileBinary(filename);
    std::size_t data_size = data.size();

    if (data_size == 0 || (data_size % 16) != 0)
    {
        throw std::runtime_error("File " + filename +
                                 " size must be non-empty and multiple of 16 bytes");
    }

    std::cout << "\n=== File: " << filename
              << " (" << data_size << " bytes) ===\n";

    // warm-up ~1s
    {
        auto start = clock::now();
        std::vector<uint8_t> ct, pt;
        while (true)
        {
            ct = cbcEncryptNoPad(data, key, iv);
            pt = cbcDecryptNoPad(ct, key, iv);

            auto now = clock::now();
            double elapsed_sec =
                std::chrono::duration<double>(now - start).count();
            if (elapsed_sec >= 1.0)
                break;
        }
        std::cout << "Warm-up done (~1s)\n";
    }

    // đo thời gian cho "blocks" block, mỗi block = rounds_per_block lần (enc+dec)
    std::vector<double> samples_ms;
    samples_ms.reserve(blocks);

    for (int b = 0; b < blocks; ++b)
    {
        auto t0 = clock::now();

        std::vector<uint8_t> ct, pt;
        for (int r = 0; r < rounds_per_block; ++r)
        {
            ct = cbcEncryptNoPad(data, key, iv);
            pt = cbcDecryptNoPad(ct, key, iv);
        }

        auto t1 = clock::now();
        double elapsed_ms =
            std::chrono::duration<double, std::milli>(t1 - t0).count();
        samples_ms.push_back(elapsed_ms);

        std::cout << "Block " << (b + 1)
                  << " time (enc+dec " << rounds_per_block
                  << " rounds): " << elapsed_ms << " ms\n";
    }

    Stats st = computeStats(samples_ms);

    // tổng dữ liệu xử lý mỗi block = rounds_per_block * data_size bytes
    double bytes_per_block = static_cast<double>(rounds_per_block) *
                             static_cast<double>(data_size);
    double mean_sec = st.mean_ms / 1000.0;
    double throughput_MBps =
        (bytes_per_block / (1024.0 * 1024.0)) / mean_sec;

    std::cout << "\n--- Statistics for file: " << filename << " ---\n";
    std::cout << "Samples (blocks): " << blocks << "\n";
    std::cout << "Mean   : " << st.mean_ms << " ms\n";
    std::cout << "Median : " << st.median_ms << " ms\n";
    std::cout << "Stddev : " << st.stddev_ms << " ms\n";
    std::cout << "95% CI : [" << st.ci_low_ms << ", "
              << st.ci_high_ms << "] ms\n";
    std::cout << "Throughput (mean, enc+dec): "
              << throughput_MBps << " MB/s\n";

    // điền vào outResult để ghi CSV
    outResult.filename = filename;
    outResult.size_bytes = data_size;
    outResult.rounds_per_block = rounds_per_block;
    outResult.blocks = blocks;
    outResult.stats = st;
    outResult.throughput_MBps = throughput_MBps;
}

// ==== ghi CSV ====

void writeCsv(const std::string &path,
              const std::vector<PerfResult> &results)
{
    std::ofstream ofs(path);
    if (!ofs)
    {
        throw std::runtime_error("Cannot open CSV file for writing: " + path);
    }

    // Header
    ofs << "File,SizeBytes,RoundsPerBlock,Blocks,"
        << "MeanMs,MedianMs,StddevMs,CILowMs,CIHighMs,ThroughputMBps\n";

    for (const auto &r : results)
    {
        ofs << "\"" << r.filename << "\""
            << "," << r.size_bytes
            << "," << r.rounds_per_block
            << "," << r.blocks
            << "," << r.stats.mean_ms
            << "," << r.stats.median_ms
            << "," << r.stats.stddev_ms
            << "," << r.stats.ci_low_ms
            << "," << r.stats.ci_high_ms
            << "," << r.throughput_MBps
            << "\n";
    }

    std::cout << "\nCSV results written to: " << path << "\n";
}

// ==== main perf ====

void printUsagePerf()
{
    std::cout
        << "Usage:\n"
        << "  aes_perf --key-hex <32 hex> --iv-hex <32 hex> [--csv result.csv] file1.bin [file2.bin ...]\n"
        << "\nExample:\n"
        << "  aes_perf --key-hex 00112233445566778899aabbccddeeff \\\n"
        << "           --iv-hex  000102030405060708090a0b0c0d0e0f \\\n"
        << "           --csv perf_results.csv \\\n"
        << "           1kb.bin 4kb.bin 16kb.bin 256kb.bin 1mb.bin 8mb.bin\n";
}

int main(int argc, char *argv[])
{
    if (argc < 5)
    {
        printUsagePerf();
        return 1;
    }

    std::string keyHex;
    std::string ivHex;
    std::string csvPath;
    std::vector<std::string> files;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--key-hex" && i + 1 < argc)
        {
            keyHex = argv[++i];
        }
        else if (arg == "--iv-hex" && i + 1 < argc)
        {
            ivHex = argv[++i];
        }
        else if (arg == "--csv" && i + 1 < argc)
        {
            csvPath = argv[++i];
        }
        else if (arg.rfind("--", 0) == 0)
        {
            std::cerr << "Unknown option: " << arg << "\n";
            printUsagePerf();
            return 1;
        }
        else
        {
            // coi là tên file
            files.push_back(arg);
        }
    }

    if (keyHex.empty() || ivHex.empty() || files.empty())
    {
        std::cerr << "Missing key/iv or files.\n";
        printUsagePerf();
        return 1;
    }

    try
    {
        uint8_t key[16];
        uint8_t iv[16];
        parseHexKeyOrIv(keyHex, key);
        parseHexKeyOrIv(ivHex, iv);

        const int rounds_per_block = 1000;
        const int blocks = 10;

        std::vector<PerfResult> allResults;
        allResults.reserve(files.size());

        for (const auto &f : files)
        {
            PerfResult res;
            runPerfForFile(f, key, iv, rounds_per_block, blocks, res);
            allResults.push_back(res);
        }

        if (!csvPath.empty())
        {
            writeCsv(csvPath, allResults);
        }
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
