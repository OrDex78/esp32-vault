# ESP32 Vault 🔐

> A DIY air-gapped hardware cryptocurrency wallet built on a $3 ESP32 chip.
> Same signing architecture as Ledger — private keys never leave the device.

![ESP32 Vault](docs/banner.png)

---

## Features

| Feature | Details |
|---|---|
| 🔑 BIP39 Mnemonic | 12-word seed, 128-bit entropy |
| 🌲 BIP32 HD Keys | ETH `m/44'/60'/0'/0/0` · BTC `m/44'/0'/0'/0/0` |
| 🔐 AES-256 Encryption | Hardware-bound key from chip eFuse |
| 📵 Air-Gapped | WiFi + Bluetooth permanently disabled at boot |
| 🖥️ OLED Display | 128×64 SH1106, 2-column menu with icons |
| 🔘 Physical Confirm | OK/Reject button for every transaction |
| 🔒 PIN Lock | 4-digit PIN, 3-attempt auto-wipe |
| 📱 QR Code | Scannable ETH address on OLED |
| 🌐 Web Companion | Chrome Web Serial app, no install needed |
| ₿ ETH + BTC | Real mainnet addresses |

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│   Web App / companion.py                               │
│   (builds tx, broadcasts)                              │
│          │                                             │
│          │ USB Serial (hash only, never seed)          │
│          ▼                                             │
│   ┌─────────────┐                                      │
│   │  ESP32 Chip │  ← private key never leaves here    │
│   │  AES-256    │                                      │
│   │  encrypted  │                                      │
│   │  seed       │                                      │
│   └─────────────┘                                      │
│          │                                             │
│          ▼                                             │
│   OLED shows tx details                                │
│   User presses OK button                               │
│   Signature sent back                                  │
│                                                        │
└─────────────────────────────────────────────────────────┘
```

---

## Hardware

### Components (~$5 total)

| Component | Spec | Cost |
|---|---|---|
| ESP32 DevKit | 38-pin, any clone | ~$2 |
| OLED Display | SH1106 128×64 SPI | ~$2 |
| Push Buttons | Tactile 6×6mm × 3 | ~$0.30 |
| Breadboard + Wires | - | ~$1 |

### Wiring

```
OLED (SPI)          ESP32
─────────────────────────
VCC           →   3.3V
GND           →   GND
SCK           →   GPIO 18
MOSI (SDA)    →   GPIO 23
CS            →   GPIO 5
DC            →   GPIO 2
RST           →   GPIO 4

Buttons (INPUT_PULLUP, active LOW)
────────────────────────────────────
UP            →   GPIO 12  ←→  GND
DOWN          →   GPIO 14  ←→  GND
OK            →   GPIO 27  ←→  GND
```

---

## Setup

### 1. Firmware

**Prerequisites:**
- VS Code + PlatformIO IDE extension

**Install:**
```bash
git clone https://github.com/OrDex78/esp32-vault
cd esp32-vault
# Open in VS Code, PlatformIO will auto-install dependencies
```

**Flash:**
```
Ctrl+Shift+P → PlatformIO: Upload
```

### 2. Python Companion

```bash
pip install pyserial mnemonic requests eth-account web3
python companion.py --port COM6 --infura https://mainnet.infura.io/v3/YOUR_KEY
```

Get a free Infura key at [infura.io](https://infura.io)

### 3. Web Companion (no install)

Open `wallet.html` in Chrome and click **Connect Device**.

---

## First Time Setup

1. Flash firmware to ESP32
2. Run `python companion.py`
3. Choose **1) Setup wallet**
4. Write down your **12 seed words** — keep them offline, never digital
5. Type `yes` to confirm
6. Set a **4-digit PIN** using device buttons
7. Your wallet is ready

---

## Usage

### Send ETH
1. Add a saved address via companion: option **5 → a**
2. On device: **Send** → pick address → set amount → OK
3. OLED shows confirmation → press OK to sign
4. Companion broadcasts → TX hash on OLED

### Check Balance
Open `wallet.html` in Chrome → Connect → Wallet tab → Refresh

### View Seed Words
Device menu → **Seed** → read warning → OK → 3 pages of 4 words

---

## Security Model

### Protected against
- ✅ Malware on PC (no seed command on serial)
- ✅ Flash dumping (AES-256 encrypted, useless without chip)
- ✅ Flash copying (key bound to specific chip's eFuse MAC)
- ✅ Remote attacks (WiFi + BT permanently disabled)
- ✅ Unauthorized transactions (physical button required)
- ✅ PIN brute force (wipes after 3 wrong attempts)

### Known limitations
- ⚠️ No secure element — physical JTAG attack possible
- ⚠️ Firmware can be replaced physically (mitigated with secure boot)

### Encryption details
```
Key = SHA256(eFuse_MAC || Chip_ID || Firmware_Salt)
Cipher = AES-256-CBC(key, random_IV, padded_seed)
Stored = [16 bytes IV] + [80 bytes ciphertext]
```

The key is never stored — derived fresh on each boot from hardware IDs.

---

## Architecture

```
src/
├── main.cpp          # Firmware (ESP32 Arduino)
├── keccak256.h       # Pure-C Keccak-256 (ETH address hashing)
└── ripemd160.h       # Pure-C RIPEMD-160 (BTC address hashing)

companion.py          # Python CLI companion
wallet.html           # Web companion (Chrome Web Serial)
platformio.ini        # PlatformIO build config
```

### Serial Protocol
```
SETSEED:<128 hex>     → store encrypted seed
ADDR_ETH              → ETH:0x...
ADDR_BTC              → BTC:1...
SIGN_ETH:<hash>:<to>:<amount> → SIG:<128 hex>
SAVEADDR:<slot>:<name>:<addr> → save frequent address
LISTADDR              → list saved addresses
RESET                 → wipe wallet
```

---

## Comparison

| | Ledger Nano S | ESP32 Vault |
|---|---|---|
| Price | $79 | ~$5 |
| Open source | Partial | ✅ Full |
| Air-gapped | ✅ | ✅ |
| Encrypted storage | ✅ | ✅ |
| BIP32/BIP39 | ✅ | ✅ |
| Physical confirm | ✅ | ✅ |
| Secure element | ✅ | ❌ |

---

## Tech Stack

```
Hardware:   ESP32 + SH1106 OLED + 3 buttons
Firmware:   C++ / Arduino / PlatformIO
Crypto:     micro-ecc (secp256k1) + mbedtls + custom Keccak/RIPEMD
Display:    U8g2
Companion:  Python 3 + eth-account + web3
Web App:    Vanilla JS + Web Serial API
Standards:  BIP32 + BIP39 + BIP44 + EIP-155
```

---

## ⚠️ Disclaimer

This is an educational project. Do not store large amounts of funds.
The author is not responsible for any loss of funds.
Always keep your 12 seed words backed up offline.

---

## License

MIT License — see [LICENSE](LICENSE.txt)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

---

*Built with ❤️ and a $3 chip*
