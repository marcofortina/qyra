#!/usr/bin/env python3
#
# Copyright (c) 2024 Marco Fortina
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

import blake3
import sys

if len(sys.argv) != 2:
    print("Usage: python blake3_hash.py <file>")
    sys.exit(1)

with open(sys.argv[1], 'rb') as f:
    file_hash = blake3.blake3(f.read()).hexdigest()
    print(file_hash)