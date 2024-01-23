# fastauth

Package suitable for the license verification written in Go.

It is suitable for the license verification section of your custom API to protect your server from unauthorized access.

## Installation

Use `go get -u`.

    go get -u github.com/colduction/fastauth

## Functions & Algorithms

### Currently added functions and algorithms

1. **Version 1 (V1)**:
    - XOR encryption with small changes
        - `Checksum`
        - `Decrypt`
        - `DecryptFromB64Raw`
        - `Encrypt`
        - `EncryptToB64Raw`
        - `Marshal`
        - `Serialize`
        - `Unmarshal`
        - `Validate`
        - `ValidateSerialized`

## Contribute

Feel free to open an issue to improve the current project for everyone, even yourself!
