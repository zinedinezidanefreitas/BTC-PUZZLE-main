#!/usr/bin/env python3
"""
puzzle.py v3 - varredura ALEATÓRIA (padrão) de chaves privadas em CPU, com secp256k1.

Backends secp256k1 (CPU):
  coincurve  -> libsecp256k1 em C (rápido).  pip install coincurve
  python     -> implementação própria (tabela de janelas + soma de pontos), sem dependências.

Exemplos:
  python puzzle.py -k 20000000000000000:3ffffffffffffffff -a 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so -w 8
  python puzzle.py -k 20000000000000000:3ffffffffffffffff -a <addr> -s 2 20 -w 8 -f puzzle66.txt
  python puzzle.py -k ... -a <addr> --backend python

Modos (-s): 0 sequencial | 1 aleatório (padrão) | 2 híbrido (+ milhões de chaves por bloco, padrão 20)
"""
import argparse
import hashlib
import multiprocessing as mp
import os
import random
import re
import time

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
BATCH = 2000


# ======================= secp256k1 em Python puro =======================
def aff_add(p, q):
    """Soma de pontos afins (None = infinito)."""
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        l = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    return x3, (l * (x1 - x3) - y1) % P


def jac_add_aff(pj, q):
    """Jacobiano + afim (madd-2007-bl). pj = (X, Y, Z) ou None."""
    if pj is None:
        return q[0], q[1], 1
    X1, Y1, Z1 = pj
    x2, y2 = q
    Z1Z1 = Z1 * Z1 % P
    U2 = x2 * Z1Z1 % P
    S2 = y2 * Z1 * Z1Z1 % P
    H = (U2 - X1) % P
    r = 2 * (S2 - Y1) % P
    if H == 0:
        if r == 0:  # mesmo ponto -> dobra via afim
            zi = pow(Z1, -1, P)
            a = aff_add((X1 * zi * zi % P, Y1 * zi ** 3 % P), (X1 * zi * zi % P, Y1 * zi ** 3 % P))
            return (a[0], a[1], 1) if a else None
        return None
    HH = H * H % P
    I = 4 * HH % P
    J = H * I % P
    V = X1 * I % P
    X3 = (r * r - J - 2 * V) % P
    Y3 = (r * (V - X3) - 2 * Y1 * J) % P
    Z3 = ((Z1 + H) ** 2 - Z1Z1 - HH) % P
    return X3, Y3, Z3


def jac_to_aff(pj):
    if pj is None:
        return None
    X, Y, Z = pj
    zi = pow(Z, -1, P)
    zi2 = zi * zi % P
    return X * zi2 % P, Y * zi2 * zi % P


class PyEC:
    """k*G com tabela de janelas de 4 bits (64 janelas x 15 pontos, calculada uma vez)."""

    def __init__(self):
        self.table = []
        base = G
        for _ in range(64):
            row, acc = [None], None
            for _ in range(15):
                acc = aff_add(acc, base)
                row.append(acc)
            self.table.append(row)
            base = aff_add(row[15], base)  # 16 * base
        self.last_k, self.last_pt = None, None

    def mul(self, k):
        r = None
        for w in range(64):
            d = (k >> (4 * w)) & 15
            if d:
                r = jac_add_aff(r, self.table[w][d])
        return jac_to_aff(r)

    def pub(self, k):
        # chave consecutiva à anterior? soma G (1 inversão) em vez de recalcular k*G
        if self.last_k is not None and k == self.last_k + 1:
            pt = aff_add(self.last_pt, G)
        else:
            pt = self.mul(k)
        self.last_k, self.last_pt = k, pt
        return (b"\x03" if pt[1] & 1 else b"\x02") + pt[0].to_bytes(32, "big")


# ======================= utilidades =======================
def valid_hex_range(option):
    m = re.fullmatch(r"(?:0x)?([0-9a-fA-F]+):(?:0x)?([0-9a-fA-F]+)", option)
    if not m:
        raise argparse.ArgumentTypeError(f"intervalo hex inválido: {option}")
    return int(m.group(1), 16), int(m.group(2), 16)


def address_to_hash160(addr):
    n = 0
    for c in addr:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(25, "big")
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError("checksum do endereço não confere")
    if raw[0] != 0:
        raise ValueError("só endereços P2PKH (começam com '1') são suportados")
    return raw[1:-4]


def get_ripemd160():
    try:
        hashlib.new("ripemd160")
        return lambda b: hashlib.new("ripemd160", b).digest()
    except ValueError:
        try:
            from Crypto.Hash import RIPEMD160
            return lambda b: RIPEMD160.new(b).digest()
        except ImportError:
            raise SystemExit("RIPEMD-160 indisponível neste Python/OpenSSL. Rode: pip install pycryptodome")


def make_matcher(target_h160, backend):
    """Retorna (match(int)->bool, nome do backend usado)."""
    rip, sha = get_ripemd160(), hashlib.sha256
    if backend in ("auto", "coincurve"):
        try:
            from coincurve import PrivateKey

            def match(i):
                pub = PrivateKey(i.to_bytes(32, "big")).public_key.format(compressed=True)
                return rip(sha(pub).digest()) == target_h160

            return match, "coincurve (libsecp256k1)"
        except ImportError:
            if backend == "coincurve":
                raise SystemExit("coincurve não instalado: pip install coincurve")
    ec = PyEC()

    def match(i):
        return rip(sha(ec.pub(i)).digest()) == target_h160

    return match, "python (secp256k1 próprio)"


def fmt_rate(kps):
    for unit, div in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if kps >= div:
            return f"{kps / div:.2f}{unit}"
    return f"{kps:.2f}"


def fmt_time(s):
    return f"{int(s // 3600)}:{int(s % 3600 // 60):02d}:{int(s % 60):02d}"


# ======================= worker =======================
def worker(lo, hi, mode, block, backend, address, h160, outfile, counter, stop, found_q):
    match, _ = make_matcher(h160, backend)
    rnd = random.SystemRandom()
    cur, blk_end, finished = lo, -1, False
    try:
        while not stop.is_set() and not finished:
            done = 0
            for _ in range(BATCH):
                if mode == 0:
                    if cur > hi:
                        finished = True
                        break
                    i, cur = cur, cur + 1
                elif mode == 1:
                    i = rnd.randint(lo, hi)
                else:
                    if cur > blk_end:
                        cur = rnd.randint(lo, hi)
                        blk_end = min(cur + block - 1, hi)
                    i, cur = cur, cur + 1
                done += 1
                if match(i):
                    key_hex = format(i, "064x")
                    with open(outfile, "a") as f:
                        f.write(f"Private Key: {key_hex}, Address: {address}\n")
                    found_q.put(key_hex)
                    stop.set()
                    break
            with counter.get_lock():
                counter.value += done
    except KeyboardInterrupt:
        pass


# ======================= main =======================
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-k", "--keyspace", type=valid_hex_range, required=True, help="inicio:fim em hex")
    ap.add_argument("-a", "--address", required=True, help="endereço BTC alvo (P2PKH)")
    ap.add_argument("-f", "--file", default="find.txt", help="arquivo de saída (Área de Trabalho)")
    ap.add_argument("-s", "--scan", nargs="*", default=["1"],
                    help="0 sequencial, 1 aleatório (padrão), 2 híbrido [milhões por bloco, padrão 20]")
    ap.add_argument("-w", "--workers", type=int, default=os.cpu_count() or 1, help="processos (padrão: nº de CPUs)")
    ap.add_argument("--backend", choices=("auto", "coincurve", "python"), default="auto")
    args = ap.parse_args()

    start, end = args.keyspace
    if start > end:
        ap.error("hex inicial maior que o final")
    if start < 1 or end >= N:
        ap.error("o intervalo precisa estar entre 1 e a ordem da curva secp256k1")
    try:
        h160 = address_to_hash160(args.address)
    except (ValueError, OverflowError) as e:
        ap.error(f"endereço inválido: {e}")
    try:
        mode = int(args.scan[0])
        millions = int(args.scan[1]) if len(args.scan) > 1 else 20
    except ValueError:
        ap.error("-s precisa de números inteiros")
    if mode not in (0, 1, 2) or millions < 1:
        ap.error("modo deve ser 0, 1 ou 2 e milhões >= 1")

    total = end - start + 1
    workers = max(1, min(args.workers, total))
    desktop = os.path.expanduser("~/Desktop")
    outfile = os.path.join(desktop if os.path.isdir(desktop) else os.getcwd(), args.file)
    _, backend_name = make_matcher(h160, args.backend)

    scan_str = {0: "Sequencial", 1: "Aleatório", 2: f"Híbrido (bloco de {millions}M)"}[mode]
    print(f"\nPUZZLE v3\n-------------------\n"
          f"Endereço alvo : {args.address}\n"
          f"Intervalo     : {start:x} - {end:x}  ({total:,} chaves)\n"
          f"Modo          : {scan_str}\n"
          f"Workers (CPU) : {workers}\n"
          f"Backend       : {backend_name}\n"
          f"Salvar em     : {outfile}\n")

    if mode == 1:  # aleatório: todos sorteiam no intervalo inteiro
        slices = [(start, end)] * workers
    else:          # sequencial/híbrido: cada worker cuida de uma fatia
        base, rem = divmod(total, workers)
        slices, cur = [], start
        for w in range(workers):
            size = base + (1 if w < rem else 0)
            slices.append((cur, cur + size - 1))
            cur += size

    counter, stop, found_q = mp.Value("Q", 0), mp.Event(), mp.Queue()
    procs = [mp.Process(target=worker, daemon=True,
                        args=(lo, hi, mode, millions * 1_000_000, args.backend, args.address,
                              h160, outfile, counter, stop, found_q))
             for lo, hi in slices]
    t0 = time.perf_counter()
    for p in procs:
        p.start()

    try:
        while any(p.is_alive() for p in procs):
            time.sleep(1)
            el = max(time.perf_counter() - t0, 1e-9)
            n = counter.value
            print(f"\r[Escaneadas {n:,} em {fmt_time(el)}] [{fmt_rate(n / el)} chaves/s]   ", end="", flush=True)
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.")
        stop.set()

    for p in procs:
        p.join(timeout=3)

    if not found_q.empty():
        print(f"\n\n*** ENCONTRADA! Private Key: {found_q.get()}\nSalva em {outfile}")
    else:
        print("\nFinalizado sem encontrar a chave.")


if __name__ == "__main__":
    mp.freeze_support()
    main()
