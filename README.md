| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-P4 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- | -------- |

# ESP32 Secure OTA with AES-256 Encryption & RSA Signature Verification

A production-ready Over-The-Air (OTA) firmware update system for ESP32 with enterprise-grade security features including AES-256-CBC encryption and RSA-3072 signature verification.

## 🔒 Security Features

- **AES-256-CBC Encryption**: Firmware is encrypted during transmission to prevent unauthorized access
- **RSA-3072 Signature Verification**: Cryptographic signatures ensure firmware authenticity and integrity
- **PKCS7 Padding Handling**: Proper padding removal for encrypted firmware
- **HTTPS Transport**: Secure communication using TLS/SSL certificates
- **Single-Pass Processing**: Memory-efficient decrypt → verify → flash workflow
- **Anti-Rollback Protection**: Version comparison prevents downgrade attacks

## 🏗️ Architecture

### Workflow

```
┌─────────────┐
│   ESP32     │
│  (Current   │
│  Firmware)  │
└──────┬──────┘
       │
       ├─────────────────────────────────────────────────────┐
       │                                                       │
       ▼                                                       ▼
┌──────────────┐                                    ┌──────────────┐
│   Download   │                                    │   Download   │
│  Manifest    │                                    │  Signature   │
│   (JSON)     │                                    │  (RSA-PSS)   │
└──────┬───────┘                                    └──────┬───────┘
       │                                                    │
       │  Compare Versions                                  │
       ▼                                                    │
┌──────────────┐                                           │
│   Download   │                                           │
│  Encrypted   │◄──────────────────────────────────────────┘
│  Firmware    │
│ (.enc file)  │
└──────┬───────┘
       │
       │  ┌─────────────────────────────────────────┐
       │  │  Single-Pass Processing:                │
       ├──┤  1. Decrypt chunk (AES-256-CBC)         │
       │  │  2. Update SHA256 hash                  │
       │  │  3. Write to OTA partition              │
       │  │  4. Repeat until complete               │
       │  │  5. Remove PKCS7 padding                │
       │  │  6. Verify RSA signature                │
       │  └─────────────────────────────────────────┘
       ▼
┌──────────────┐
│  Signature   │
│   Verified   │
│      ✓       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Set Boot    │
│  Partition   │
│  & Reboot    │
└──────────────┘
```

## 📋 Prerequisites

### Hardware
- ESP32 development board (tested on ESP32-WROOM-32)
- USB cable for flashing and debugging

### Software
- **ESP-IDF v5.5.1** or later
- **Python 3.8+** for OTA server
- **OpenSSL** for key generation and encryption
- **Git** for version control

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/basarenaplaya/OTA-idf.git
cd OTA-idf/advanced_https_ota
```

### 2. Generate Cryptographic Keys

```bash
# Generate RSA-3072 key pair for firmware signing
openssl genrsa -out private_key.pem 3072
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Generate AES-256 key and IV
openssl rand -hex 32  # AES-256 key (32 bytes)
openssl rand -hex 16  # IV (16 bytes)
```

### 3. Configure Security Credentials

Edit `main/secrets/config.h`:

```c
// Your manifest URL
const char* MANIFEST_URL = "https://192.168.0.177:5000/manifest.json";

// AES-256 Key (32 bytes) - from openssl rand -hex 32
static const uint8_t AES_KEY[32] = {
  0x44, 0xca, 0xaf, 0x3c, 0x5b, 0xa9, 0xd2, 0xe0,
  // ... rest of key
};

// AES IV (16 bytes) - from openssl rand -hex 16
static const uint8_t AES_IV[16] = {
  0x58, 0xc2, 0x2b, 0x80, 0x24, 0x51, 0x55, 0xe0,
  // ... rest of IV
};

// Current firmware version
const char* FIRMWARE_VERSION = "1.0";

// RSA Public Key - paste content from public_key.pem
const char* PUBLIC_KEY = R"KEY(
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA...
-----END PUBLIC KEY-----
)KEY";

// Server SSL certificate
const char* GITHUB_ROOT_CA_CERT = R"CERT(
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIU...
-----END CERTIFICATE-----
)CERT";
```

### 4. Build and Flash Initial Firmware

```bash
# Set ESP-IDF environment
$env:IDF_PATH = 'C:/Espressif/frameworks/esp-idf-v5.5.1/'

# Build the project
idf.py build

# Flash to ESP32
idf.py -p COM3 flash monitor
```

### 5. Set Up OTA Server

```bash
cd ../OTA_Server

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Start server (auto-detects IP and updates manifest)
python server.py
```

### 6. Prepare New Firmware for OTA

```bash
# 1. Update version in config.h
# const char* FIRMWARE_VERSION = "1.1";

# 2. Build new firmware
idf.py build

# 3. Copy firmware binary
cp build/advanced_https_ota.bin ../OTA_Server/firmware/firmware.bin

# 4. Encrypt firmware with AES-256-CBC
cd ../OTA_Server/firmware
openssl enc -aes-256-cbc -in firmware.bin -out firmware.enc \
  -K YOUR_HEX_KEY -iv YOUR_HEX_IV

# 5. Sign the ORIGINAL (unencrypted) firmware
openssl dgst -sha256 -sign ../private_key.pem \
  -out signature.bin firmware.bin

# 6. Update manifest version
# Edit manifest.json: "version": "1.1"
```

## 📁 Project Structure

```
advanced_https_ota/
├── main/
│   ├── firmware.c                 # Main OTA implementation
│   ├── CMakeLists.txt             # Build configuration
│   └── secrets/
│       └── config.h               # Security credentials (DO NOT COMMIT)
├── build/                         # Build output directory
├── sdkconfig                      # ESP-IDF configuration
├── CMakeLists.txt                 # Top-level build file
└── README.md                      # This file

OTA_Server/
├── server.py                      # Flask HTTPS server
├── manifest.json                  # Version manifest (auto-updated)
├── requirements.txt               # Python dependencies
├── certs/                         # SSL certificates
│   ├── cert.pem
│   └── key.pem
├── firmware/                      # Firmware files
│   ├── firmware.enc               # Encrypted firmware
│   └── signature.bin              # RSA signature
├── private_key.pem                # RSA private key (DO NOT COMMIT)
└── public_key.pem                 # RSA public key
```

## ⚙️ Configuration

### ESP32 Configuration (`sdkconfig`)

Key configurations:
- **Partition Table**: `partitions_example_with_ble.csv`
- **Flash Size**: 4MB
- **OTA Data Partition**: 0x2000 bytes at 0xd000
- **Factory App**: 0x1C0000 bytes at 0x10000
- **OTA_0**: 0x1C0000 bytes at 0x1d0000
- **OTA_1**: 0x1C0000 bytes at 0x390000

### Server Configuration

The server automatically:
- Detects local IP address on startup
- Updates `manifest.json` URLs with current IP
- Enables auto-reload on file changes (debug mode)
- Serves firmware over HTTPS on port 5000

## 🔐 Security Best Practices

### Key Management
1. **Never commit** `private_key.pem` or `config.h` to version control
2. Use different keys for development and production
3. Rotate keys periodically
4. Store private keys in secure hardware (HSM) for production

### Encryption
- AES-256-CBC provides strong encryption for firmware transmission
- IV (Initialization Vector) should be unique per encryption session
- PKCS7 padding is automatically handled by the system

### Signature Verification
- Sign the **unencrypted** firmware binary
- RSA-3072 provides strong cryptographic security
- Signature is verified **after** decryption and padding removal
- Failed signature verification prevents firmware installation

### Network Security
- Always use HTTPS for firmware distribution
- Validate SSL certificates on ESP32
- Consider certificate pinning for production
- Use VPN or private network when possible

## 🧪 Testing

### Monitor OTA Process

```bash
idf.py monitor
```

Expected output:
```
I (9235) firmware: Current firmware version: 1.0
I (9235) firmware: Update Check: Current=1.0, Available=1.1
I (9245) firmware: New version found. Downloading signature...
I (10775) firmware: Successfully downloaded signature (384 bytes)
I (10775) firmware: Starting secure OTA: decrypt → verify → flash...
I (11325) firmware: First decrypted bytes: e9 06 02 20 e8 15 08 40
I (27765) firmware: Removed 16 bytes of PKCS7 padding
I (27775) firmware: Verifying signature of decrypted firmware...
I (27825) firmware: ✓ Signature verification PASSED
I (28445) firmware: OTA update successful!
I (28445) firmware: ✓ Secure OTA complete! Rebooting in 2 seconds...
```

### Test Update Interval

Default: 5 minutes (300000ms)

Modify in `config.h`:
```c
const long UPDATE_CHECK_INTERVAL_MS = 60000; // 1 minute for testing
```

## 🐛 Troubleshooting

### Stack Overflow Errors
- **Cause**: Large buffers allocated on stack
- **Solution**: Buffers now use heap allocation (malloc/free)
- **Stack Size**: Task stack increased to 12KB

### Signature Verification Failed
- **Check**: Sign the **unencrypted** firmware.bin, not firmware.enc
- **Check**: Key/IV in config.h match encryption command
- **Check**: Public key matches private key used for signing

### Decryption Issues
- **Invalid magic byte**: Key or IV mismatch
- **Check**: Convert hex key/IV correctly (not ASCII characters)
- Example: `44ca` = `0x44, 0xca` (not `0x34, 0x34, 0x63, 0x61`)

### Connection Failed
- **Check**: ESP32 and server on same network
- **Check**: Firewall allows port 5000
- **Check**: IP address in manifest.json is correct
- **Check**: SSL certificate matches server IP

### OTA Partition Full
- **Increase partition size** in `partitions_example_with_ble.csv`
- **Reduce firmware size**: Disable unused features in `sdkconfig`

## 📊 Performance Metrics

- **Memory Usage**: ~8KB RAM for buffers and crypto contexts
- **Download Speed**: Depends on network (typically 50-200 KB/s)
- **Decryption Overhead**: ~5-10% additional time vs plain OTA
- **Flash Write Speed**: ~100 KB/s
- **Typical Update Time**: 30-60 seconds for 1MB firmware

## 🔄 Update Workflow

### Development Cycle

1. **Modify code** and increment version in `config.h`
2. **Build** new firmware: `idf.py build`
3. **Copy** binary to server: `cp build/*.bin ../OTA_Server/firmware/firmware.bin`
4. **Encrypt**: `openssl enc -aes-256-cbc -in firmware.bin -out firmware.enc -K <key> -iv <iv>`
5. **Sign**: `openssl dgst -sha256 -sign private_key.pem -out signature.bin firmware.bin`
6. **Update** manifest version
7. **Wait** for ESP32 to check for updates (or reboot)

### Automated Deployment

Consider creating a deployment script:

```bash
#!/bin/bash
# deploy_ota.sh

VERSION=$1
KEY="your_hex_key"
IV="your_hex_iv"

# Build firmware
idf.py build

# Copy and encrypt
cp build/advanced_https_ota.bin ../OTA_Server/firmware/firmware.bin
cd ../OTA_Server/firmware
openssl enc -aes-256-cbc -in firmware.bin -out firmware.enc -K $KEY -iv $IV

# Sign
openssl dgst -sha256 -sign ../private_key.pem -out signature.bin firmware.bin

# Update manifest
jq ".version = \"$VERSION\"" ../manifest.json > ../manifest.tmp.json
mv ../manifest.tmp.json ../manifest.json

echo "Deployed version $VERSION"
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is provided as-is for educational and commercial use.

## 🙏 Acknowledgments

- **ESP-IDF Framework**: Espressif Systems
- **mbedTLS**: ARM Limited
- **Flask**: Pallets Projects
- **OpenSSL**: OpenSSL Software Foundation

## 📞 Support

For issues and questions:
- **GitHub Issues**: [OTA-idf/issues](https://github.com/basarenaplaya/OTA-idf/issues)
- **ESP-IDF Forum**: [esp32.com](https://esp32.com)

## 🔮 Future Enhancements

- [ ] Delta updates (binary diff)
- [ ] Compressed firmware support
- [ ] Multiple device management
- [ ] Rollback on boot failure
- [ ] A/B partition switching
- [ ] Remote logging and diagnostics
- [ ] Web-based management interface
- [ ] Database backend for version tracking

---

**Built with ❤️ for secure IoT deployments**
