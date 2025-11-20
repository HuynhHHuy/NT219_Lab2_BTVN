#!/bin/bash
g++ -std=c++17 -O2 src/aes.cpp src/cbc.cpp src/main.cpp -o aes_tool
echo "Built aes_tool"
