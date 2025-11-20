#  AES-128 CBC – Lab 2 (Cryptography)

Dự án này triển khai **AES-128**, **CBC mode**, **PKCS#7 padding** và các công cụ kiểm thử/benchmark theo yêu cầu của **Lab 2 – NT219 (Cryptography & Applications)**.

Toàn bộ mã nguồn được viết bằng **C++17 thuần**, **không sử dụng bất kỳ thư viện crypto ngoài**, bám sát chuẩn:

- **AES-128 (FIPS-197)**  
- **CBC mode (NIST SP 800-38A)**  
- **AESAVS KAT files** (CBCGFSbox128, CBCVarKey128, CBCVarTxt128…)

Dự án bao gồm:
- Bộ mã AES-128 thuần C++
- CBC + PKCS#7 + CBC No-Pad
- CLI tool: `aes_tool`
- Benchmark tool: `aes_perf`
- Self-test chuẩn (FIPS-197 + SP800-38A)
- Export CSV cho performance
- Phục vụ viết báo cáo

---

##  Cấu trúc thư mục

```text
.
├── src/
│   ├── aes.h / aes.cpp          # AES-128 core
│   ├── cbc.h / cbc.cpp          # CBC, PKCS#7, CBC-no-pad
│   ├── main.cpp                 # aes_tool CLI (enc/dec/selftest)
│   └── perf.cpp                 # aes_perf benchmark tool
│
├── tests/
│   ├── CBCGFSbox128.rsp
│   ├── CBCKeySbox128.rsp
│   ├── CBCVarKey128.rsp
│   └── CBCVarTxt128.rsp         # NIST AESAVS KAT files
│
├── perf_results.csv             # (nếu đã chạy benchmark)
├── README.md
└── *.bin                        # test files (1kb, 4kb, 16kb, 256kb, 1mb, 8mb)

```
---
## Build
## Windows (MinGW-w64)
```text
g++ -std=c++17 -O2 src\aes.cpp src\cbc.cpp src\main.cpp -o aes_tool.exe
g++ -std=c++17 -O2 src\aes.cpp src\cbc.cpp src\perf.cpp -o aes_perf.exe
```

## Linux
```text
g++ -std=c++17 -O2 src/aes.cpp src/cbc.cpp src/main.cpp -o aes_tool
g++ -std=c++17 -O2 src/aes.cpp src/cbc.cpp src/perf.cpp -o aes_perf
```

## Sử dụng công cụ aes_tool
1️⃣ Self-test (đảm bảo tính đúng đắn của AES)
aes_tool selftest


Output sẽ bao gồm:

- FIPS-197 AES-128 ECB test: OK

- SP800-38A CBC AES-128 test: OK

- All self-tests passed.

2️⃣ Mã hoá (CBC + PKCS#7)
```
./aes_tool.exe enc \
  --in plain.txt \
  --out cipher.bin \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex  000102030405060708090a0b0c0d0e0f
```
3️⃣ Giải mã
```
./aes_tool.exe dec \
  --in cipher.bin \
  --out plain2.txt \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex  000102030405060708090a0b0c0d0e0f
```
4️⃣ Chế độ không padding (CBC no-pad)

(dùng để test với SP800-38A hoặc dữ liệu bội số 16)

- aes_tool enc --no-pad ...
- aes_tool dec --no-pad ...

## Benchmark với aes_perf

Công cụ aes_perf đo hiệu năng:

- Warm-up ~1 giây

- 1 block = 1000 round (enc + dec)

- 10 block → lấy mean, median, stddev, 95% CI

- Xuất file CSV để phân tích trong Excel

## Chạy benchmark
aes_perf \
  --key-hex 00112233445566778899aabbccddeeff \
  --iv-hex  000102030405060708090a0b0c0d0e0f \
  --csv perf_results.csv \
  1kb.bin 4kb.bin 16kb.bin 256kb.bin 1mb.bin 8mb.bin

Output bao gồm:

- Thời gian từng block (10 block)

- Mean, Median, Stddev

- 95% Confidence Interval

- Throughput (MB/s)


