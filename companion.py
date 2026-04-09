#!/usr/bin/env python3
"""
Hardware Wallet Companion
Install: pip install pyserial mnemonic requests eth-account web3 pywalletconnect==1.6.2
Usage:   python companion.py --port COM6 --infura https://mainnet.infura.io/v3/KEY
"""

import serial
import serial.tools.list_ports
import time, sys, os, json, hashlib, argparse, requests, threading

try:
    from eth_account import Account
    from eth_account._utils.legacy_transactions import (
        encode_transaction,
        serializable_unsigned_transaction_from_dict,
    )
    ETH_OK = True
except ImportError:
    ETH_OK = False

try:
    from web3 import Web3
    W3_OK = True
except ImportError:
    W3_OK = False

try:
    from mnemonic import Mnemonic
    MN_OK = True
except ImportError:
    MN_OK = False

try:
    from pywalletconnect.client import WCClient
    WC_OK = True
except ImportError:
    WC_OK = False

WC_PROJECT_ID = "5dca26e3ce9c06aabbfcd9490a4b3239"
BAUD    = 115200
TIMEOUT = 30


# ════════════════════════════════════════════════════════════
#  Address checksum helper
# ════════════════════════════════════════════════════════════

def to_checksum(addr):
    """Convert any ETH address to proper EIP-55 checksum format."""
    if not addr: return addr
    addr = addr.strip()
    if not addr.startswith("0x"):
        addr = "0x" + addr
    if W3_OK:
        try:
            return Web3.to_checksum_address(addr)
        except: pass
    return addr.lower()


# ════════════════════════════════════════════════════════════
#  Serial
# ════════════════════════════════════════════════════════════

def list_ports():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No serial ports found."); return []
    for i, p in enumerate(ports):
        print("  [%d] %s - %s" % (i, p.device, p.description))
    return [p.device for p in ports]

def pick_port(arg_port=None):
    if arg_port: return arg_port
    ports = list_ports()
    if not ports: sys.exit(1)
    if len(ports) == 1:
        print("Using " + ports[0]); return ports[0]
    return ports[int(input("Select port: ").strip())]

def send_cmd(ser, cmd, timeout=TIMEOUT):
    ser.reset_input_buffer()
    ser.write((cmd + '\n').encode())
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ser.in_waiting:
            resp = ser.readline().decode(errors='replace').strip()
            if resp: return resp
        time.sleep(0.05)
    return ""


# ════════════════════════════════════════════════════════════
#  BIP39
# ════════════════════════════════════════════════════════════

def generate_mnemonic():
    if not MN_OK: print("pip install mnemonic"); sys.exit(1)
    return Mnemonic("english").to_mnemonic(os.urandom(16))

def mnemonic_to_seed(words, passphrase=""):
    if MN_OK: return Mnemonic.to_seed(words, passphrase)
    return hashlib.pbkdf2_hmac("sha512",
        words.encode(), ("mnemonic"+passphrase).encode(), 2048)


# ════════════════════════════════════════════════════════════
#  Wallet setup
# ════════════════════════════════════════════════════════════

def cmd_setup(ser):
    mnemonic = generate_mnemonic()
    seed     = mnemonic_to_seed(mnemonic)
    print("\n" + "="*52)
    print("  YOUR 12-WORD MNEMONIC - WRITE THIS DOWN NOW")
    print("="*52)
    for i, w in enumerate(mnemonic.split()):
        print("  %2d. %s" % (i+1, w))
    print("="*52)
    if input("\nWritten down? (yes/no): ").strip().lower() != "yes":
        print("Cancelled."); return
    # Save seed words BEFORE sending to device (device may request immediately)
    import os
    save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_words.txt")
    with open(save_path, "w") as f:
        f.write(mnemonic)
    print("  Saved seed_words.txt")

    print("Sending seed to device...")
    # Send seed - device may respond with OK then SEND_WORDS
    ser.reset_input_buffer()
    ser.write(("SETSEED:" + seed.hex() + "\n").encode())
    
    # Read responses - expect OK and possibly SEND_WORDS
    resp = ""
    deadline = time.time() + 15
    while time.time() < deadline:
        if ser.in_waiting:
            line = ser.readline().decode(errors='replace').strip()
            if line == "OK":
                resp = "OK"
            elif line == "SEND_WORDS":
                # Device requesting seed words - send immediately
                try:
                    import os
                    save_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_words.txt")
                    with open(save_path) as f:
                        words = f.read().strip()
                    ser.write(("WORDS:" + words + "\n").encode())
                    print("  Sent words to device")
                except Exception as e:
                    print("  Could not send words: " + str(e))
        if resp == "OK":
            time.sleep(0.3)  # small wait for SEND_WORDS
            break
        time.sleep(0.05)
    
    if resp == "OK":
        print("Stored!\n"); time.sleep(1)
        # Send words to device
        ser.write(("WORDS:" + mnemonic + "\n").encode())
        time.sleep(0.5)
        eth = send_cmd(ser,"ADDR_ETH").replace("ETH:","").strip()
        btc = send_cmd(ser,"ADDR_BTC").replace("BTC:","").strip()
        print("  ETH: " + eth)
        print("  BTC: " + btc)
        _save_local(eth, btc)
    else:
        print("Error: " + resp)

def _save_local(eth, btc):
    with open("wallet_info.json","w") as f:
        json.dump({"eth":eth,"btc":btc},f)
    print("  Saved wallet_info.json")

def _load_local():
    try:
        with open("wallet_info.json") as f: return json.load(f)
    except: return None

def cmd_addresses(ser):
    eth = send_cmd(ser,"ADDR_ETH").replace("ETH:","").strip()
    btc = send_cmd(ser,"ADDR_BTC").replace("BTC:","").strip()
    print("\n  ETH: " + eth)
    print("  BTC: " + btc + "\n")
    try:
        r   = requests.get(
            "https://blockstream.info/api/address/"+btc, timeout=5).json()
        sat = r.get("chain_stats",{}).get("funded_txo_sum",0) \
            - r.get("chain_stats",{}).get("spent_txo_sum",0)
        print("  BTC balance: %.8f BTC" % (sat/1e8))
    except: print("  BTC balance: (lookup failed)")


# ════════════════════════════════════════════════════════════
#  Sign + broadcast ETH
# ════════════════════════════════════════════════════════════

def _sign_and_broadcast(ser, tx_params, rpc_url):
    if not ETH_OK: print("pip install eth-account"); return None

    # Get and checksum our address
    raw_addr = send_cmd(ser,"ADDR_ETH").replace("ETH:","").strip()
    eth_addr = to_checksum(raw_addr)

    # Nonce
    nonce_r = requests.post(rpc_url, json={
        "jsonrpc":"2.0","method":"eth_getTransactionCount",
        "params":[eth_addr,"latest"],"id":1},timeout=10).json()
    if "error" in nonce_r:
        print("Nonce error: " + str(nonce_r["error"])); return None
    nonce = int(nonce_r["result"],16)

    # Chain ID
    chain_r  = requests.post(rpc_url, json={
        "jsonrpc":"2.0","method":"eth_chainId",
        "params":[],"id":1},timeout=10).json()
    chain_id = int(chain_r["result"],16)

    # Gas price
    try:
        gp_r      = requests.post(rpc_url, json={
            "jsonrpc":"2.0","method":"eth_gasPrice",
            "params":[],"id":1},timeout=10).json()
        gas_price = int(gp_r["result"],16)
    except: gas_price = 20*10**9

    # Parse and checksum destination
    to_addr   = to_checksum(tx_params.get("to",""))
    value_hex = tx_params.get("value","0x0")
    value_wei = int(value_hex,16) if isinstance(value_hex,str) else int(value_hex)
    value_eth_f = value_wei/1e18
    data_hex  = tx_params.get("data","0x") or "0x"
    gas_raw   = tx_params.get("gas","0x5208")
    gas_limit = int(gas_raw,16) if isinstance(gas_raw,str) else int(gas_raw)

    is_contract = len(data_hex) > 2
    label = ("%.6f ETH" % value_eth_f) if not is_contract else "Contract/Swap"

    print("\n  From  : " + eth_addr)
    print("  To    : " + to_addr)
    print("  Value : " + label)
    print("  Gas   : %d gwei" % (gas_price//10**9))

    tx = {
        "nonce":    nonce,
        "gasPrice": gas_price,
        "gas":      gas_limit,
        "to":       to_addr,
        "value":    value_wei,
        "data":     bytes.fromhex(data_hex.replace("0x","")),
        "chainId":  chain_id,
    }

    unsigned = serializable_unsigned_transaction_from_dict(tx)
    tx_hash  = unsigned.hash()

    print("\n  >> Check OLED: press OK to approve, UP to reject")

    resp = send_cmd(ser,
        "SIGN_ETH:%s:%s:%s" % (tx_hash.hex(), to_addr[:20], label),
        timeout=60)

    if not resp.startswith("SIG:"):
        print("  Not signed: " + resp); return None

    sig_hex = resp[4:]
    r_val   = int(sig_hex[:64],16)
    s_val   = int(sig_hex[64:128],16)

    print("  Signed! Broadcasting...")

    for vc in [0,1]:
        v   = vc + 2*chain_id + 35
        raw = encode_transaction(unsigned, vrs=(v,r_val,s_val))
        res = requests.post(rpc_url, json={
            "jsonrpc":"2.0","method":"eth_sendRawTransaction",
            "params":["0x"+raw.hex()],"id":1},timeout=10).json()
        if "result" in res:
            txid = res["result"]
            print("\n  SUCCESS!")
            print("  TX: " + txid)
            print("  View: https://etherscan.io/tx/" + txid)
            return txid

    print("  Broadcast failed: " + str(res.get("error",res)))
    return None

def cmd_send_eth(ser, infura_url=None):
    if not infura_url:
        infura_url = input("RPC URL: ").strip()

    print("\nSend ETH")
    print("-"*40)
    to_addr    = input("To address : ").strip()
    amount_str = input("Amount ETH : ").strip()

    try:
        amount_eth = float(amount_str)
    except:
        print("Invalid amount."); return

    if amount_eth <= 0:
        print("Amount must be > 0"); return

    print("\nReview:")
    print("  To     : " + to_addr)
    print("  Amount : %.6f ETH" % amount_eth)
    if input("\nContinue? (yes/no): ").strip().lower() != "yes":
        print("Cancelled."); return

    _sign_and_broadcast(ser, {
        "to":    to_addr,
        "value": hex(int(amount_eth * 10**18)),
        "data":  "0x",
        "gas":   "0x5208",
    }, infura_url)


# ════════════════════════════════════════════════════════════
#  WalletConnect
# ════════════════════════════════════════════════════════════

def cmd_walletconnect(ser, infura_url=None):
    if not WC_OK:
        print("pip install pywalletconnect==1.6.2"); return

    info = _load_local()
    if not info:
        eth = send_cmd(ser,"ADDR_ETH").replace("ETH:","").strip()
        btc = send_cmd(ser,"ADDR_BTC").replace("BTC:","").strip()
        if not eth: print("Run Setup first."); return
        info={"eth":eth,"btc":btc}; _save_local(eth,btc)

    eth_addr = info["eth"]
    chain_id = 1

    if not infura_url:
        infura_url = input("RPC URL: ").strip()

    print("\nYour ETH: " + eth_addr)
    print("In DApp: Connect Wallet -> WalletConnect -> Copy URI")
    wc_uri = input("Paste WalletConnect URI: ").strip()
    if not wc_uri.startswith("wc:"):
        print("Invalid URI."); return

    try:
        WCClient.set_project_id(WC_PROJECT_ID)
        wc = WCClient.from_wc_uri(wc_uri)
        print("Connecting...")
        req_id, req_data, _ = wc.open_session()
        wc.reply_session_request(req_id, chain_id, eth_addr)
        print("Connected! DApp sees: " + eth_addr)
        print("Waiting for requests... (Ctrl+C to stop)\n")
    except Exception as e:
        print("Connection error: " + str(e)); return

    try:
        while True:
            try:
                msg = wc.get_message()
            except Exception:
                time.sleep(1); continue

            if msg is None:
                time.sleep(0.2); continue

            if not isinstance(msg,(list,tuple)) or len(msg)<2:
                continue

            req_id     = msg[0]
            req_method = msg[1]
            req_params = msg[2] if len(msg)>2 else []

            if not req_method: continue

            print("\n[DApp] " + str(req_method))

            if req_method == "eth_sendTransaction":
                tx_p = req_params[0] if req_params else {}
                txh  = _sign_and_broadcast(ser, tx_p, infura_url)
                if txh: wc.reply(req_id, txh)
                else:   wc.reject(req_id)

            elif req_method == "personal_sign":
                msg_hex = req_params[0] if req_params else "0x"
                try:
                    mb = bytes.fromhex(msg_hex.replace("0x",""))
                    mt = mb.decode("utf-8",errors="replace")
                except: mb=b""; mt=msg_hex
                print("  Message: " + mt[:60])
                prefix = ("\x19Ethereum Signed Message:\n%d"%len(mb)).encode()
                h      = hashlib.sha3_256(prefix+mb).digest()
                resp   = send_cmd(ser,
                    "SIGN_ETH:%s:personal_sign:%dchars"%(h.hex(),len(mt)),
                    timeout=60)
                if resp.startswith("SIG:"):
                    wc.reply(req_id,"0x"+resp[4:]); print("  Signed!")
                else:
                    wc.reject(req_id); print("  Rejected")

            elif req_method == "eth_accounts":
                wc.reply(req_id, [eth_addr])

            elif req_method in ("net_version","eth_chainId"):
                wc.reply(req_id, str(chain_id))

            elif req_method == "wallet_switchEthereumChain":
                wc.reply(req_id, None)

    except KeyboardInterrupt:
        print("\nDisconnecting...")
        try: wc.close()
        except: pass
        print("Done.")


# ════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════

def cmd_manage_addrs(ser):
    print("\nSaved Address Manager")
    print("-"*40)
    print("  a) Add address")
    print("  l) List addresses")
    print("  b) Back")
    choice = input("\n> ").strip().lower()
    if choice == "a":
        idx = int(input("Slot (0-4): ").strip())
        if idx < 0 or idx > 4:
            print("Invalid slot."); return
        name = input("Nickname (max 15 chars): ").strip()[:15]
        addr = input("ETH Address (0x...): ").strip()
        resp = send_cmd(ser, "SAVEADDR:%d:%s:%s" % (idx, name, addr))
        print("Device: " + resp)
    elif choice == "l":
        resp = send_cmd(ser, "LISTADDR")
        print(resp)
        # Read more lines
        import time
        time.sleep(0.5)
        while ser.in_waiting:
            print(ser.readline().decode(errors="replace").strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port",   help="COM port e.g. COM6")
    parser.add_argument("--infura", help="Infura RPC URL")
    args = parser.parse_args()

    port = pick_port(args.port)
    print("\nConnecting to " + port + "...")
    try:
        ser = serial.Serial(port, BAUD, timeout=5)
        time.sleep(2)
    except serial.SerialException as e:
        print("Cannot open: " + str(e)); sys.exit(1)

    cmds = {
        "1": ("Setup wallet",                 lambda: cmd_setup(ser)),
        "2": ("Show addresses",               lambda: cmd_addresses(ser)),
        "3": ("Send ETH",                     lambda: cmd_send_eth(ser, args.infura)),
        "4": ("Connect DApp (WalletConnect)", lambda: cmd_walletconnect(ser, args.infura)),
        "5": ("Manage saved addresses",        lambda: cmd_manage_addrs(ser)),
        "6": ("Reset wallet",                 lambda: (send_cmd(ser,"RESET"),print("Reset OK"))),
        "q": ("Quit", None),
    }

    print("\nConnected. Commands:")
    for k,(d,_) in cmds.items(): print("  %s) %s" % (k, d))

    # Background thread to listen for device messages
    def device_listener():
        while True:
            try:
                if ser.in_waiting:
                    line = ser.readline().decode(errors="replace").strip()
                    if not line: continue
                    if line.startswith("SEND_REQUEST:"):
                        parts = line.split(":")
                        if len(parts) >= 3:
                            to_addr = parts[1]
                            amount  = parts[2]
                            print("\n\n[Device send request]")
                            print("  To    : " + to_addr)
                            print("  Amount: " + amount)
                            try:
                                amt_eth = float(amount.replace(" ETH",""))
                                if args.infura:
                                    txh = _sign_and_broadcast(ser, {
                                        "to":    to_addr,
                                        "value": hex(int(amt_eth * 10**18)),
                                        "data":  "0x",
                                        "gas":   "0x5208",
                                    }, args.infura)
                                    if txh:
                                        ser.write(("TX:" + txh + "\n").encode())
                                        print("  Sent TX to device: " + txh)
                                    else:
                                        ser.write(b"ERR:broadcast failed\n")
                                else:
                                    print("  No Infura URL -- run with --infura flag")
                                    ser.write(b"ERR:no infura\n")
                            except Exception as e:
                                print("  Send error: " + str(e))
                                ser.write(("ERR:" + str(e) + "\n").encode())
                            print("\n> ", end="", flush=True)
                    elif line == "SEND_WORDS":
                        # Device is asking for seed words
                        # We stored them during setup
                        try:
                            with open("seed_words.txt") as f:
                                words = f.read().strip()
                            ser.write(("WORDS:" + words + "\n").encode())
                            print("\n[Sent seed words to device]")
                        except Exception:
                            print("\n[seed_words.txt not found - run setup again]")
                        print("\n> ", end="", flush=True)
                    else:
                        # Print other device messages
                        if line:
                            print("\n[Device] " + line)
                            print("\n> ", end="", flush=True)
            except Exception:
                pass
            time.sleep(0.1)

    listener = threading.Thread(target=device_listener, daemon=True)
    listener.start()

    while True:
        choice = input("\n> ").strip().lower()
        if choice == "q": break
        if choice in cmds and cmds[choice][1]:
            try: cmds[choice][1]()
            except Exception as e: print("Error: " + str(e))
        else: print("Unknown.")

    ser.close(); print("Bye.")

if __name__ == "__main__":
    main()
