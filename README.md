# C-Secret-Manager

## Overview
A secure in-memory secret store written in C, using XOR-based symmetric encryption to protect secrets at rest. Demonstrates key vault architecture patterns.

## Quick Start (1-Click Build)

```bash
git clone https://github.com/skylerblue333/C-Secret-Manager.git
cd C-Secret-Manager
mkdir build && cd build
cmake .. && make
./secret_manager
```

## Features
- XOR cipher for at-rest encryption
- Key-value secret storage
- Master key rotation support
