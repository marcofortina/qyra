#!/bin/env python3
#
# Copyright (c) 2024 Marco Fortina
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

import json
import sys

# Helper function to convert a hexadecimal string into a C++ vector
def hex_string_to_vector(hex_string):
    # Split the hex string into pairs of characters (bytes)
    bytes_array = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    # Build the C++ vector as a list of unsigned char
    vector = ', '.join(f'0x{byte}' for byte in bytes_array)
    return f"{{ {vector} }}"

# Function to convert JSON data to a C++ header file
def convert_json_to_header(json_file, header_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    with open(header_file, 'w') as f:
        f.write("#ifndef SOLUTIONS_H\n")
        f.write("#define SOLUTIONS_H\n\n")
        f.write("#include <vector>\n\n")
        f.write("// Structure to hold JSON data\n")
        f.write("struct SolutionData {\n")
        f.write("    std::vector<unsigned char> header;\n")
        f.write("    std::vector<unsigned char> nonce;\n")
        f.write("    std::vector<unsigned char> solution;\n")
        f.write("};\n\n")
        
        f.write("// Declare the array with the JSON data\n")
        f.write("const SolutionData solutions[] = {\n")
        
        for entry in data:
            header_vector = hex_string_to_vector(entry['header'])
            nonce_vector = hex_string_to_vector(entry['nonce'])
            solution_vector = hex_string_to_vector(entry['solution'])
            
            f.write(f'    {{ {header_vector}, {nonce_vector}, {solution_vector} }},\n')
        
        f.write("};\n\n")
        f.write("// Number of solutions\n")
        f.write("const size_t numSolutions = sizeof(solutions) / sizeof(SolutionData);\n\n")
        f.write("#endif // SOLUTIONS_H\n")

# Main function to run the script
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: json_to_h.py <input_json> <output_h>")
        sys.exit(1)
    
    input_json = sys.argv[1]
    output_h = sys.argv[2]
    convert_json_to_header(input_json, output_h)