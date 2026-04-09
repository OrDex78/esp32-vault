# Contributing to ESP32 Vault

Thank you for your interest in contributing! This project welcomes contributions of all kinds.

## Ways to Contribute

- 🐛 **Bug reports** — open an issue with steps to reproduce
- 💡 **Feature ideas** — open an issue with `[FEATURE]` prefix
- 🔧 **Code** — fork, branch, PR
- 📖 **Documentation** — fix typos, add examples
- 🔐 **Security** — see security policy below

## Development Setup

```bash
git clone https://github.com/OrDex78/esp32-vault
cd esp32-vault
# VS Code + PlatformIO for firmware
# Python 3.14+ for companion
pip install pyserial mnemonic requests eth-account web3
```

## Pull Request Guidelines

1. Fork the repo and create a branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Test on real hardware (ESP32 + OLED)
4. Update README if needed
5. Open a PR with a clear description

## Security Policy

**Please do NOT open public issues for security vulnerabilities.**

If you find a security issue, email directly or open a private GitHub security advisory.

Security contributions that will be accepted:
- Stronger key derivation (HMAC eFuse integration)
- Secure boot implementation
- Side-channel attack mitigations
- Better RNG seeding

## Coding Style

- C++: follow existing style, comments in English
- Python: PEP 8, type hints welcome
- Keep functions small and single-purpose
- Security-critical code must have clear comments explaining why

## Roadmap

- [ ] Secure boot eFuse burn
- [ ] ATECC608 secure element integration
- [ ] Auto-lock after idle
- [ ] BTC broadcasting (standalone)
- [ ] Passphrase support (BIP39 25th word)
- [ ] Transaction history
- [ ] 3D printed enclosure
- [ ] WalletConnect v2 full support
