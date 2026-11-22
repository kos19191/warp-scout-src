#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фейковый AWG/WireGuard-эндпоинт для интеграционной проверки WarpScout.

Это НЕЗАВИСИМАЯ реализация серверной части handshake WireGuard
(Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s), написанная на Python, чтобы проверить
Kotlin-клиент не «самим собой», а чужим кодом. Если warp-scout договаривается с этим
скриптом — он договаривается и с живым Cloudflare WARP ровно в той же части
(сам handshake); остальное решает поведение сети.

Что делает:
  • слушает UDP;
  • молчит на всё, что не является ровно 148-байтной инициацией — то есть junk-пакеты
    AWG ведут себя как в реальности: WireGuard принимает пакет только точного размера;
  • проверяет mac1 и таймстамп, отвечает корректным handshake response (92 байта);
  • в режиме --require-cookie сначала шлёт cookie reply (64 байта) и только после
    инициации с правильным mac2 = BLAKE2s-MAC(cookie) отвечает handshake response.

Зависимости: Python 3.9+, `cryptography` (X25519 + ChaCha20-Poly1305).
    pip install cryptography

Запуск:
    python3 tools/fake_warp_endpoint.py --test-key --port 34567
    # и в другом терминале:
    java -cp <classpath> dev.warpscout.cli.MainKt selftest --integration 127.0.0.1:34567

Свои ключи: --private-key <base64>, а полученный публичный ключ впишите в конфиг как
PeerPublicKey. Без ключей генерируем случайный и печатаем публичный.
"""

import argparse
import base64
import hashlib
import hmac
import os
import socket
import struct
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:  # pragma: no cover
    sys.exit("Нужен пакет cryptography:  pip install cryptography")

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

INITIATION_LEN = 148
RESPONSE_LEN = 92
COOKIE_MSG_LEN = 64

TYPE_INITIATION = 1
TYPE_RESPONSE = 2
TYPE_COOKIE = 3
TYPE_TRANSPORT = 4

ZERO32 = b"\x00" * 32
ZERO12 = b"\x00" * 12

# Детерминированный ключ, который ожидает SelfCheck.liveIntegration():
# Kotlin: ByteArray(32) { (it * 2 + 1).toByte() }.also { it[31] = 0 }
TEST_PEER_PRIV = bytes([(i * 2 + 1) % 256 for i in range(32)])[:31] + b"\x00"


# ------------------------------------------------------------------ примитивы

def blake2s(data: bytes, key: bytes = b"", size: int = 32) -> bytes:
    return hashlib.blake2s(data, digest_size=size, key=key).digest()


def mac_blake2s(key: bytes, msg: bytes, size: int = 32) -> bytes:
    """HMAC-BLAKE2s (как Blake2s.hmac в Kotlin)."""
    return hmac.new(key, msg, hashlib.blake2s).digest() if size == 32 else \
        _hmac_blake2s_short(key, msg, size)


def _hmac_blake2s_short(key: bytes, msg: bytes, size: int) -> bytes:
    """HMAC с усечённым выводом: сначала HMAC-256, потом HASH(32-байтного результата)."""
    full = hmac.new(key, msg, hashlib.blake2s).digest()
    return blake2s(full, size=size)


def kdf_two(ck: bytes, ikm: bytes):
    """KDF из двух выходов (MixKey с ключом): (новый ck, key)."""
    temp = mac_blake2s(ck, ikm)
    ck1 = mac_blake2s(temp, b"\x01")
    key = mac_blake2s(temp, ck1 + b"\x02")
    return ck1, key


def kdf_mix_hash(ck: bytes, ikm: bytes):
    """MixKey+MixHash для psk: (новый ck, hash-добавка, key)."""
    temp = mac_blake2s(ck, ikm)
    ck1 = mac_blake2s(temp, b"\x01")
    t2 = mac_blake2s(temp, ck1 + b"\x02")
    key = mac_blake2s(temp, t2 + b"\x03")
    return ck1, t2, key


def aead_seal(key: bytes, pt: bytes, h: bytes):
    """message_encrypt: шифруем AAD=h, nonce=0, затем MIX_HASH(ct)."""
    ct = ChaCha20Poly1305(key).encrypt(ZERO12, pt, h)
    return ct, blake2s(h + ct)


def aead_open(key: bytes, ct: bytes, h: bytes):
    """message_decrypt: ядро микширует ВЕСЬ ct (src_len поля), тег внутри ct."""
    pt = ChaCha20Poly1305(key).decrypt(ZERO12, ct, h)
    return pt, blake2s(h + ct)


def public_of(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()


def dh(priv: bytes, pub: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


# ------------------------------------------------- XChaCha20-Poly1305 (cookie)

CONSTANTS = struct.unpack("<4I", b"expand 32-byte k")


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]; x[d] = ((x[d] << 16) | (x[d] >> 16)) & 0xFFFFFFFF
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]; x[b] = ((x[b] << 12) | (x[b] >> 20)) & 0xFFFFFFFF
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] ^= x[a]; x[d] = ((x[d] << 8) | (x[d] >> 24)) & 0xFFFFFFFF
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] ^= x[c]; x[b] = ((x[b] << 7) | (x[b] >> 25)) & 0xFFFFFFFF


def _chacha_block(key: bytes, counter: int, nonce12: bytes) -> bytes:
    """Блок ChaCha20 (RFC 8439 §2.3): 12-байтный nonce + 32-битный счётчик + обратная связь."""
    orig = list(CONSTANTS) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce12))
    x = list(orig)
    for _ in range(10):
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13); _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12); _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    x = [(v + s) & 0xFFFFFFFF for v, s in zip(x, orig)]
    return struct.pack("<16I", *x)


def _chacha20_xor(key: bytes, nonce12: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + i // 64, nonce12)
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20: без обратной связи, вывод = строки 0 и 3 (вектор §2.2.1)."""
    x = list(CONSTANTS) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13); _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12); _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    return struct.pack("<8I", *x[0:4], *x[12:16])


def _poly1305(key32: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key32[0:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key32[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = ((acc + blk) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b + b"\x00" * ((16 - len(b) % 16) % 16)


def xchacha20poly1305_seal(key: bytes, nonce24: bytes, pt: bytes, aad: bytes) -> bytes:
    sub = hchacha20(key, nonce24[:16])
    iv = b"\x00\x00\x00\x00" + nonce24[16:24]      # 12 байт: 4 нуля || последние 8 байт nonce
    poly_key = _chacha_block(sub, 0, iv)[:32]
    ct = _chacha20_xor(sub, iv, 1, pt)
    mac = _pad16(aad) + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return ct + _poly1305(poly_key, mac)


# ------------------------------------------------------------------ сервер

class FakeWarpServer:
    def __init__(self, priv: bytes, require_cookie: bool = False, verbose: bool = True):
        self.priv = priv
        self.pub = public_of(priv)
        self.require_cookie = require_cookie
        self.verbose = verbose
        # состояние по адресу клиента: два теста подряд не отравляют друг друга
        self.cookies: dict = {}
        self.stats = {"junk": 0, "initiations": 0, "responses": 0, "cookies": 0,
                      "rejected": 0, "transport": 0, "echo": 0, "replayed": 0}
        # Самая новая принятая метка времени (TAI64N) по статическому ключу клиента: как настоящий
        # сервер (ядро Linux, wireguard-go), инициацию с меткой не новее этой считаем повтором.
        self.newest_ts: dict = {}
        # ключи сессии после handshake (чтобы уметь эхо-ить транспорт)
        self.sessions: dict = {}

    def log(self, msg: str):
        if self.verbose:
            print(msg, flush=True)

    def handle(self, pkt: bytes, addr) -> bytes | None:
        """Вернуть байты ответа или None (молчим)."""
        if len(pkt) >= 32 and struct.unpack_from("<I", pkt, 0)[0] == TYPE_TRANSPORT:
            return self.handle_transport(pkt, addr)
        if len(pkt) != INITIATION_LEN:
            self.stats["junk"] += 1
            self.log(f"  {addr}: {len(pkt)} байт — не инициация, молчим")
            return None
        if struct.unpack_from("<I", pkt, 0)[0] != TYPE_INITIATION:
            self.stats["junk"] += 1
            return None
        self.stats["initiations"] += 1
        client_sender = struct.unpack_from("<I", pkt, 4)[0]
        e = pkt[8:40]

        ck = blake2s(CONSTRUCTION)
        h = blake2s(ck + IDENTIFIER)
        h = blake2s(h + self.pub)

        # e
        h = blake2s(h + e)
        ck = mac_blake2s(mac_blake2s(ck, e), b"\x01")
        # es
        ck, key = kdf_two(ck, dh(self.priv, e))
        # s
        try:
            client_static, h = aead_open(key, pkt[40:88], h)
        except Exception:
            self.stats["rejected"] += 1
            self.log(f"  {addr}: не расшифровался статический ключ — молчим")
            return None
        # ss
        ck, key = kdf_two(ck, dh(self.priv, client_static))
        # {t}
        try:
            ts, h = aead_open(key, pkt[88:116], h)
        except Exception:
            self.stats["rejected"] += 1
            self.log(f"  {addr}: битый таймстамп — молчим")
            return None
        if blake2s(pkt[:116], key=blake2s(LABEL_MAC1 + self.pub), size=16) != pkt[116:132]:
            self.stats["rejected"] += 1
            self.log(f"  {addr}: mac1 не совпал — молчим")
            return None
        self.log(f"  {addr}: инициация валидна, tai64n={ts.hex()}")

        if self.require_cookie:
            expected = self.cookies.get(addr)
            if expected is None:
                return self.make_cookie(pkt, client_sender, addr)
            if blake2s(pkt[:132], key=expected, size=16) != pkt[132:148]:
                self.stats["rejected"] += 1
                self.log(f"  {addr}: нет правильного mac2(cookie) — молчим")
                return None

        # Защита от повтора — после проверки cookie, как в wireguard-go: метки сравниваются
        # побайтно (memcmp), и принимается только строго более новая.
        newest = self.newest_ts.get(client_static)
        if newest is not None and ts <= newest:
            self.stats["rejected"] += 1
            self.stats["replayed"] += 1
            self.log(f"  {addr}: метка времени не новее прошлой ({ts.hex()} <= {newest.hex()}) — повтор, молчим")
            return None
        self.newest_ts[client_static] = ts

        return self.make_response(pkt, h, ck, e, client_static, client_sender, addr)

    def handle_transport(self, pkt: bytes, addr) -> bytes | None:
        """Transport-пакет: расшифровать и вернуть то же содержимое обратно (эхо).

        Это проверка именно data plane: ключи сессии, порядок счётчиков, nonce и AAD
        сверяются с независимой реализацией, а не с нашей же функцией.
        """
        sess = self.sessions.get(addr)
        if sess is None:
            self.log(f"  {addr}: транспорт до handshake — молчим")
            return None
        self.stats["transport"] += 1
        receiver = struct.unpack_from("<I", pkt, 4)[0]
        counter = int.from_bytes(pkt[8:16], "little")
        if receiver != sess["my_index"] or counter <= sess["rcounter"]:
            self.log(f"  {addr}: transport не по индексу/повтор — молчим")
            return None
        nonce = b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")
        try:
            payload = ChaCha20Poly1305(sess["recv"]).decrypt(nonce, pkt[16:], b"")
        except Exception:
            payload = None
        if payload is None:
            self.log(f"  {addr}: не расшифровался transport-пакет — молчим")
            return None
        sess["rcounter"] = counter
        # эхо
        sc = sess["scounter"]
        ct = ChaCha20Poly1305(sess["send"]).encrypt(b"\x00\x00\x00\x00" + sc.to_bytes(8, "little"),
                                                          payload, b"")
        out = struct.pack("<IIQ", TYPE_TRANSPORT, sess["remote_index"], sc) + ct
        sess["scounter"] = sc + 1
        self.stats["echo"] += 1
        self.log(f"  {addr}: эхо transport (payload={len(payload)} байт, counter={counter})")
        return out

    def make_cookie(self, pkt: bytes, client_sender: int, addr) -> bytes:
        cookie = os.urandom(16)
        self.cookies[addr] = cookie
        nonce = os.urandom(24)
        key = blake2s(LABEL_COOKIE + self.pub)
        enc = xchacha20poly1305_seal(key, nonce, cookie, pkt[116:132])
        out = bytearray(COOKIE_MSG_LEN)
        struct.pack_into("<II", out, 0, TYPE_COOKIE, client_sender)
        out[8:32] = nonce
        out[32:64] = enc
        self.stats["cookies"] += 1
        self.log(f"  {addr}: под нагрузкой — посылаю cookie reply (64 байта)")
        return bytes(out)

    def make_response(self, pkt, h, ck, e, client_static, client_sender, addr) -> bytes:
        resp_priv = os.urandom(32)
        resp_pub = public_of(resp_priv)
        h = blake2s(h + resp_pub)
        ck = mac_blake2s(mac_blake2s(ck, resp_pub), b"\x01")
        ck = mac_blake2s(mac_blake2s(ck, dh(resp_priv, e)), b"\x01")            # ee
        ck = mac_blake2s(mac_blake2s(ck, dh(resp_priv, client_static)), b"\x01")  # se
        ck, t2, key = kdf_mix_hash(ck, ZERO32)                                    # psk
        h = blake2s(h + t2)
        # derive_keys(ck): out1 = HMAC(HMAC(ck,''),1), out2 = HMAC(temp, out1||2)
        _tmp = mac_blake2s(ck, b"")
        ck_out1 = mac_blake2s(_tmp, b"\x01")
        ck_out2 = mac_blake2s(_tmp, ck_out1 + b"\x02")
        enc_nothing = ChaCha20Poly1305(key).encrypt(ZERO12, b"", h)              # {}

        out = bytearray(RESPONSE_LEN)
        struct.pack_into("<III", out, 0, TYPE_RESPONSE, 0x5A5A5A5A, client_sender)
        out[12:44] = resp_pub
        out[44:60] = enc_nothing
        out[60:76] = blake2s(bytes(out[:60]), key=blake2s(LABEL_MAC1 + client_static), size=16)
        self.sessions[addr] = {
            "recv": ck_out1,          # responder принимает out1
            "send": ck_out2,          # responder отправляет out2
            "my_index": 0x5A5A5A5A,
            "remote_index": client_sender,
            "rcounter": -1,
            "scounter": 0,
        }
        self.stats["responses"] += 1
        # одноразовый cookie: после успешного обмена забываем, чтобы следующий клиент
        # снова прошёл через cookie-цикл (интеграционному тесту нужна именно такая картина)
        if self.require_cookie:
            self.cookies.pop(addr, None)
        self.log(f"  {addr}: отвечаю handshake response (92 байта)")
        return bytes(out)

    def serve(self, host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        print(f"слушаю udp://{host}:{port}", flush=True)
        try:
            while True:
                data, addr = sock.recvfrom(2048)
                reply = self.handle(data, addr)
                if reply:
                    sock.sendto(reply, addr)
        except KeyboardInterrupt:
            print(f"\nостановлен; статистика: {self.stats}")


def main():
    ap = argparse.ArgumentParser(description="Фейковый AWG/WireGuard-эндпоинт (UDP)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--private-key", help="base64 приватного ключа (32 байта)")
    ap.add_argument("--test-key", action="store_true",
                    help="детерминированный ключ из SelfCheck (для интеграционного теста)")
    ap.add_argument("--require-cookie", action="store_true",
                    help="первую инициацию отбить cookie reply (проверка cookie-retry в клиенте)")
    ap.add_argument("--selftest", action="store_true", help="прогнать внутренние векторы и выйти")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if args.private_key:
        priv = base64.b64decode(args.private_key)
        if len(priv) != 32:
            sys.exit("--private-key: нужно 32 байта в base64")
    else:
        priv = TEST_PEER_PRIV if args.test_key else os.urandom(32)

    srv = FakeWarpServer(priv, require_cookie=args.require_cookie, verbose=not args.quiet)
    print("Fake WARP/AWG endpoint (независимая серверная реализация handshake)")
    print(f"  peer PublicKey = {base64.b64encode(srv.pub).decode()}")
    if not (args.test_key or args.private_key):
        print("  ключ сгенерирован случайно — впишите PublicKey в конфиг как PeerPublicKey")
    if args.require_cookie:
        print("  режим cookie: первая инициация получает cookie reply")
    srv.serve(args.host, args.port)


def selftest():
    """Проверка собственных примитивов по опубликованным векторам."""
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'OK ' if good else 'FAIL'} {name}")

    check("blake2s('abc')",
          blake2s(b"abc").hex(),
          "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    check("hchacha20 (draft-irtf-cfrg-xchacha §2.2.1)",
          hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex(),
          "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
          b"the future, sunscreen would be it.")
    check("xchacha20poly1305 (Appendix A.1)",
          xchacha20poly1305_seal(bytes(range(0x80, 0xA0)), bytes(range(0x40, 0x58)), pt,
                                 bytes.fromhex("50515253c0c1c2c3c4c5c6c7")).hex(),
          "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
          "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
          "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
          "21f9664c97637da9768812f615c68b13b52e"
          "c0875924c1c7987947deafd8780acf49")
    check("x25519 (RFC 7748 §6.1)",
          public_of(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).hex(),
          "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    print("векторы: " + ("все OK" if ok else "ЕСТЬ ПРОВАЛЫ"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
