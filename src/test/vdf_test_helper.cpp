// Copyright (c) 2026 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <uint256.h>
#include <vdf/VdfGenerate.h>

#include <charconv>
#include <cstdint>
#include <iostream>
#include <string_view>

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cerr << "usage: vdf_test_helper <prev-hash-hex> <iterations>\n";
        return 1;
    }
    const auto hash = uint256::FromHex(argv[1]);
    uint64_t iterations{0};
    const std::string_view iteration_arg{argv[2]};
    const auto [end, error] = std::from_chars(
        iteration_arg.data(), iteration_arg.data() + iteration_arg.size(), iterations);
    if (!hash || error != std::errc{} || end != iteration_arg.data() + iteration_arg.size()) {
        std::cerr << "invalid helper argument\n";
        return 1;
    }
    const auto proof = vdf::GenerateProofForTesting(*hash, iterations, 1024);
    if (proof.empty()) {
        std::cerr << "VDF generation failed\n";
        return 2;
    }
    static constexpr char HEX[] = "0123456789abcdef";
    for (const uint8_t byte : proof) {
        std::cout << HEX[byte >> 4] << HEX[byte & 0x0f];
    }
    std::cout << '\n';
    return 0;
}
