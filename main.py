# eth_watcher_full.py
import os
import time
import json
import binascii
import asyncio
import requests

try:
    import websockets
except Exception:
    websockets = None

# ------------------- CONFIG -------------------
ALCHEMY_KEY = os.getenv("ALCHEMY_KEY") or "glOloDIxM-zdr717l9YLW"
HTTP = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"
WS   = f"wss://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"

POLL_IF_WS_FAIL = True
POLL_INTERVAL_SECONDS = 1.5
HTTP_TIMEOUT = 12
PRINT_TX_CONTRACT_CREATIONS = True
# ----------------------------------------------

# --- JSON-RPC HTTP helper ---
def rpc(method: str, params: list):
    payload = {"jsonrpc": "2.0", "id": int(time.time()), "method": method, "params": params}
    r = requests.post(HTTP, json=payload, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    res = r.json()
    if "error" in res:
        raise RuntimeError(res["error"])
    return res.get("result")

# --- basic helpers ---
def hex_to_int(h):
    return int(h, 16) if isinstance(h, str) else h

def get_block_by_hash(block_hash: str, full_tx: bool = True):
    return rpc("eth_getBlockByHash", [block_hash, full_tx])

def get_block_by_number(num_hex: str, full_tx: bool = True):
    return rpc("eth_getBlockByNumber", [num_hex, full_tx])

def get_tx_receipt(tx_hash: str):
    return rpc("eth_getTransactionReceipt", [tx_hash])

# ---------------- ERC-20 metadata helpers ----------------
SEL_NAME = "0x06fdde03"
SEL_SYMBOL = "0x95d89b41"
SEL_DECIMALS = "0x313ce567"

def hex_to_bytes(h: str) -> bytes:
    if not h:
        return b""
    h = h[2:] if h.startswith("0x") else h
    if len(h) % 2:
        h = "0" + h
    return binascii.unhexlify(h)

def decode_abi_string(hexdata: str):
    """Try decode ABI return for string (handles bytes32 and dynamic)."""
    if not hexdata or hexdata == "0x":
        return None
    data = hex_to_bytes(hexdata)
    # small payload => likely bytes32
    if len(data) <= 32:
        return data.rstrip(b"\x00").decode("utf-8", errors="ignore") or None
    # dynamic ABI: offset(32) | length(32) | data
    if len(data) >= 64:
        try:
            str_len = int.from_bytes(data[32:64], "big")
            str_bytes = data[64:64+str_len]
            return str_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return data.rstrip(b"\x00").decode("utf-8", errors="ignore")
    return None

def call_contract_simple_read(contract_addr: str, selector: str):
    call_obj = {"to": contract_addr, "data": selector}
    try:
        return rpc("eth_call", [call_obj, "latest"])
    except Exception:
        return None

def fetch_erc20_metadata(contract_addr: str):
    """Return dict {name, symbol, decimals} where values may be None."""
    out = {"name": None, "symbol": None, "decimals": None}
    # name
    try:
        r = call_contract_simple_read(contract_addr, SEL_NAME)
        if r:
            out["name"] = decode_abi_string(r)
    except Exception:
        out["name"] = None
    # symbol
    try:
        r = call_contract_simple_read(contract_addr, SEL_SYMBOL)
        if r:
            out["symbol"] = decode_abi_string(r)
    except Exception:
        out["symbol"] = None
    # decimals
    try:
        r = call_contract_simple_read(contract_addr, SEL_DECIMALS)
        if r and isinstance(r, str) and r.startswith("0x"):
            out["decimals"] = int(r, 16)
    except Exception:
        out["decimals"] = None
    return out

# ----------------- Main watcher -----------------
# Simple in-memory cache to avoid repeated metadata calls
_seen_contracts = {}  # contract_addr -> metadata dict or "NOT_ERC20"

def fetch_and_print_token_metadata(contract_addr: str, tx_hash: str, frm: str, gas: int):
    # check cache
    if contract_addr in _seen_contracts:
        meta = _seen_contracts[contract_addr]
        if meta == "NOT_ERC20":
            print(
                f"➕ 1 Contract created :\n"
                f"  • Etherscan: https://etherscan.io/address/{contract_addr}\n"
                f"  • TokenSniffer: https://tokensniffer.com/token/eth/{contract_addr}\n"
                f"  • Uniswap: https://app.uniswap.org/explore/tokens/ethereum/{contract_addr}"
            )

            return
        print(
                f"➕ 2 Contract created :\n"
                f"  • Etherscan: https://etherscan.io/address/{contract_addr}\n"
                f"  • TokenSniffer: https://tokensniffer.com/token/eth/{contract_addr}\n"
                f"  • Uniswap: https://app.uniswap.org/explore/tokens/ethereum/{contract_addr}"
            )
        
        print(f"       → name: {meta.get('name') or 'N/A'} | symbol: {meta.get('symbol') or 'N/A'} | decimals: {meta.get('decimals') if meta.get('decimals') is not None else 'N/A'}")
        return

    # not cached: fetch
    meta = fetch_erc20_metadata(contract_addr)
    # consider it non-ERC20 if all fields None and the contract has tiny bytecode (or just mark NOT_ERC20)
    if not any([meta.get("name"), meta.get("symbol"), meta.get("decimals") is not None]):
        _seen_contracts[contract_addr] = "NOT_ERC20"
        print(
                f"➕ 3 Contract created :\n"
                f"  • Etherscan: https://etherscan.io/address/{contract_addr}\n"
                f"  • TokenSniffer: https://tokensniffer.com/token/eth/{contract_addr}\n"
                f"  • Uniswap: https://app.uniswap.org/explore/tokens/ethereum/{contract_addr}"
            )
        
    else:
        _seen_contracts[contract_addr] = meta
        print(
                f"➕ 4 Contract created :\n"
                f"  • Etherscan: https://etherscan.io/address/{contract_addr}\n"
                f"  • TokenSniffer: https://tokensniffer.com/token/eth/{contract_addr}\n"
                f"  • Uniswap: https://app.uniswap.org/explore/tokens/ethereum/{contract_addr}"
            )
        
        print(f"       → name: {meta.get('name') or 'N/A'} | symbol: {meta.get('symbol') or 'N/A'} | decimals: {meta.get('decimals') if meta.get('decimals') is not None else 'N/A'}")

async def ws_watch():
    if websockets is None:
        print("[WS] websockets package not installed. Skipping WS.")
        return False

    print(f"[WS] connecting to {WS} ...")
    try:
        # add Origin header to improve chances of acceptance
        extra_headers = [("Origin", "https://eth-mainnet.g.alchemy.com"), ("User-Agent", "eth-watcher/1.0")]
        async with websockets.connect(WS, ping_interval=20, ping_timeout=20, extra_headers=extra_headers) as ws:
            sub = {"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe", "params": ["newHeads"]}
            await ws.send(json.dumps(sub))
            ack = await ws.recv()
            print(f"[WS] subscribed: {ack}")

            while True:
                raw = await ws.recv()
                data = json.loads(raw)
                params = data.get("params")
                if not params:
                    continue
                head = params.get("result") or {}
                number_hex = head.get("number")
                block_hash = head.get("hash")
                if not number_hex or not block_hash:
                    continue
                block_num = hex_to_int(number_hex)
                print(f"\n🧱 [WS] New block #{block_num} | {block_hash}")

                if not PRINT_TX_CONTRACT_CREATIONS:
                    continue

                try:
                    block = get_block_by_hash(block_hash, full_tx=True)
                    txs = (block or {}).get("transactions", []) or []
                    created = 0
                    for tx in txs:
                        tx_hash = tx.get("hash")
                        if tx.get("to") is None and tx_hash:
                            try:
                                rcpt = get_tx_receipt(tx_hash)
                                contract_addr = rcpt.get("contractAddress")
                                if contract_addr:
                                    created += 1
                                    frm = tx.get("from")
                                    gas = int(tx.get("gas", "0x0"), 16)
                                    fetch_and_print_token_metadata(contract_addr, tx_hash, frm, gas)
                                    # tiny delay to avoid bursting RPC if many contracts in block
                                    time.sleep(0.12)
                            except Exception as e:
                                print(f"   [warn] receipt error {tx_hash}: {e}")
                    if created:
                        print(f"   ✔ {created} new contract(s) in block {block_num}")
                except Exception as e:
                    print(f"[warn] cannot inspect block {block_num}: {e}")

    except Exception as e:
        print(f"[WS] WebSocket error: {type(e).__name__}: {e}")
        return False

    return True

def http_poll_watch():
    print("[POLL] Starting HTTP poller (fallback).")
    last_block = None
    try:
        while True:
            try:
                blk_hex = rpc("eth_blockNumber", [])
            except Exception as e:
                print(f"[POLL] rpc error: {e}. retrying in {POLL_INTERVAL_SECONDS}s")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            if not blk_hex:
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            blk_num = hex_to_int(blk_hex)
            if last_block is None:
                last_block = blk_num
                print(f"[POLL] current block #{blk_num}")
            elif blk_num > last_block:
                for n in range(last_block + 1, blk_num + 1):
                    num_hex = hex(n)
                    try:
                        block = get_block_by_number(num_hex, full_tx=True)
                    except Exception as e:
                        print(f"[POLL] unable to fetch block #{n}: {e}")
                        continue
                    print(f"\n🧱 [POLL] New block #{n}")
                    if not PRINT_TX_CONTRACT_CREATIONS:
                        continue
                    txs = (block or {}).get("transactions", []) or []
                    created = 0
                    for tx in txs:
                        tx_hash = tx.get("hash")
                        if tx.get("to") is None and tx_hash:
                            try:
                                rcpt = get_tx_receipt(tx_hash)
                                contract_addr = rcpt.get("contractAddress")
                                if contract_addr:
                                    created += 1
                                    frm = tx.get("from")
                                    gas = int(tx.get("gas", "0x0"), 16)
                                    fetch_and_print_token_metadata(contract_addr, tx_hash, frm, gas)
                                    time.sleep(0.12)
                            except Exception as e:
                                print(f"   [warn] receipt error {tx_hash}: {e}")
                    if created:
                        print(f"   ✔ {created} new contract(s) in block {n}")
                last_block = blk_num
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("[POLL] stopped by user.")

def main():
    print("[START] Ethereum watcher (Alchemy) - ERC20 metadata")
    print("HTTP:", HTTP)
    print("WS:  ", WS)
    # quick http check
    try:
        r = rpc("eth_blockNumber", [])
        print(f"[CHECK] eth_blockNumber OK -> {r}")
    except Exception as e:
        print(f"[ERROR] HTTP RPC failed: {e}. Check your key or app network settings.")
        return

    # try websockets
    if websockets is None:
        print("[INFO] websockets not installed. Running HTTP poll fallback.")
        http_poll_watch()
        return

    try:
        ok = asyncio.run(ws_watch())
    except KeyboardInterrupt:
        print("\n[STOP] interrupted by user.")
        return
    except Exception as e:
        print(f"[MAIN] ws_watch raised: {e}")
        ok = False

    if not ok and POLL_IF_WS_FAIL:
        print("[MAIN] WS unavailable -> switching to HTTP poll.")
        http_poll_watch()

if __name__ == "__main__":
    main()
