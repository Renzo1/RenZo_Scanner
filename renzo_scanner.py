# Title: RenZo Scanner
# Author: Kris RenZo @krisrenzo (twitter)
# Version: v0.1.0

import os
import re

print("RenZo Scanner v.0.1.0. \nBuilt with Love! \nvisit https://github.com/Renzo1/Security_Auditors_Starter_Pack for more details")

def analyze_solidity_code(file_path):
    red_flags = [
    "suicide", "selfdestruct", "delegatecall", "assembly", "tx.origin",
    "ecrecover", "callcode", "staticcall", "send", "transfer",
    "block.timestamp", "block.number", "this.balance", "delete", "external",
    "public", "gasleft", "blockhash", "extcodesize", "abi.encodePacked",
    "abi.encode", "constant", "true", "false", "for", "while",
    "block.blockhash(", "msg.gas", "throw", "sha3(", "callcode(", "suicide(",
    "constant", "var", "abi.encodePacked(", "assembly", "ABIEncoderV2", "v0.7.",
    "v0.6", "v0.5.", "v0.4.", "initialize", "initializer", "Initializable",
    "ERC20", "ERC777", "ERC1400", "Owner", "mapping", "permit",
    "some_collision", "EIP-2612", "DOMAIN_SEPARATOR", "event", "using", "this", " / ",
    "create2", "owner == address(0)", "owner==address(0)", "todo", "to do", "to-do",
    "address(msg.sender)", "transferFrom", "int", "modifier", "=+", "ERC621",
    "ERC884", "ERC721", "using", "msg.value", "uint256(", "uint128(",
    "uint96(", "uint64(", "uint32(", "uint16(", "uint8(", "call",
    # Add more red flags as needed

    ]

    with open(file_path, 'r', encoding='utf-8') as file:
        code_lines = file.readlines()

    flagged_lines = []

    for line_number, line in enumerate(code_lines, start=1):
        for flag in red_flags:
            if re.search(fr'{re.escape(flag)}', line):
                flagged_lines.append((line_number, flag))

    return flagged_lines

def analyze_folder(folder_path):
    flagged_files = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".sol"):
                file_path = os.path.join(root, file)
                flags_found = analyze_solidity_code(file_path)

                if flags_found:
                    flagged_files.append((file_path, flags_found))

    return flagged_files

if __name__ == "__main__":
    folder_path = input("Enter the path to the folder containing Solidity files: ")
    flagged_files = analyze_folder(folder_path)

    if flagged_files:
        print("Red flags found in the following files:")
        for file_path, flags_found in flagged_files:
            print(f"\nFile: {file_path}")
            for line_number, flag in flags_found:
                print(f"  Line {line_number}: {flag}")
    else:
        print("No red flags found in any Solidity files.")

