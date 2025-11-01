import os
import asyncio
import json
import time
import requests
import websockets

# ==== CONFIG ==============================================================
# 👉 Méthode 1 (RECOMMANDÉE) : via variable d’environnement
ALCHEMY_KEY = os.getenv("ALCHEMY_KEY")

# 👉 Méthode 2 (RAPIDE POUR TESTS) : clé en dur (TU PEUX TESTER AVEC LA TIENNE)
# NOTE : évite de commit/partager une clé en dur. Regénère ta clé ensuite.
if not ALCHEMY_KEY:
    ALCHEMY_KEY = "glOloDIxM-zdr717l9YLW"  # <-- ta clé fournie (pense à la régénérer ensuite)

HTTP = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"
WS   = f"wss://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"

# Réglages
PRINT_TX_CONTRACT_CREATIONS = True   # True = inspecte chaque bloc pour repérer les créations de contrats (simple et utile)
HTTP_TIMEOUT = 15
# ==========================================================================


def rpc(method: str, params: list):
    """Appel JSON-RPC HTTP côté Alchemy."""
    payload = {"jsonrpc": "2.0", "id": int(time.time()), "method": method, "params": params}
    r = requests.post(HTTP, json=payload, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    out = r.json()
    if "error" in out:
        raise RuntimeError(out["error"])
    return out.get("result")


def hex_to_int(h: str) -> int:
    return int(h, 16) if isinstance(h, str) else h


def get_block_by_hash(block_hash: str, full_tx: bool = True):
    return rpc("eth_getBlockByHash", [block_hash, full_tx])


def get_tx_receipt(tx_hash: str):
    return rpc("eth_getTransactionReceipt", [tx_hash])


async def watch_new_blocks():
    """S'abonne aux nouveaux blocs (newHeads) via WebSocket Alchemy et log les infos clés.
       Optionnellement, détecte les créations de contrats dans chaque bloc."""
    print(f"[INFO] Connexion WS Alchemy… {WS}")
    async with websockets.connect(WS, ping_interval=20, ping_timeout=20) as ws:
        # Subscribe to newHeads (nouveaux blocs)
        sub = {"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe", "params": ["newHeads"]}
        await ws.send(json.dumps(sub))
        ack = await ws.recv()
        print(f"[WS] Abonné newHeads → {ack}")

        while True:
            raw = await ws.recv()
            data = json.loads(raw)
            if data.get("method") != "eth_subscription":
                continue

            params = data.get("params", {})
            head = (params.get("result") or {})
            number_hex = head.get("number")
            block_hash = head.get("hash")
            if not number_hex or not block_hash:
                continue

            block_num = hex_to_int(number_hex)
            print(f"\n🧱  Nouveau bloc #{block_num} | {block_hash}")

            if not PRINT_TX_CONTRACT_CREATIONS:
                continue

            # Récupérer le bloc (avec transactions complètes) et détecter les créations de contrats
            try:
                block = get_block_by_hash(block_hash, full_tx=True)
                txs = block.get("transactions", []) if block else []
                created = 0
                for tx in txs:
                    tx_hash = tx.get("hash")
                    # Heuristique création de contrat : to == None
                    if tx.get("to") is None and tx_hash:
                        # Confirmer via le receipt (contractAddress != None)
                        try:
                            rcpt = get_tx_receipt(tx_hash)
                            contract_addr = rcpt.get("contractAddress")
                            if contract_addr:
                                created += 1
                                frm = tx.get("from")
                                gas = int(tx.get("gas", "0x0"), 16)
                                print(f"   ➕ Contract created: {contract_addr} | tx: {tx_hash} | from: {frm} | gas: {gas}")
                        except Exception as e:
                            print(f"   [warn] receipt error {tx_hash}: {e}")
                if created:
                    print(f"   ✔ {created} nouveau(x) contrat(s) détecté(s) dans le bloc {block_num}")
            except Exception as e:
                print(f"[warn] Impossible d’inspecter le bloc {block_num}: {e}")


def main():
    print("[START] Ethereum watcher (Alchemy / newHeads + contract creations)")
    print("HTTP:", HTTP)
    print("WS:  ", WS)
    try:
        asyncio.run(watch_new_blocks())
    except KeyboardInterrupt:
        print("\n[STOP] Interrompu par l’utilisateur.")


if __name__ == "__main__":
    main()
