#!/usr/bin/env python3
"""Independent decryptor + verifier for the fixtures written by make_fixtures.py (stdlib only).

For each fixture: derive keystream from key.txt (none for plain/), decrypt db pages, walk the WAL
(salts + cumulative checksum over stored bytes, stop at first break, keep frames only up to the
last commit frame), overlay committed pages, truncate to the commit's db size, set header bytes
18/19 = 1, open with sqlite3, integrity_check, compare against expected_rows.json.
"""
import hashlib, json, os, sqlite3, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def keystream(key, n):
    # RC4 KSA + PRGA written independently (array-based)
    s = bytearray(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    while len(out) < n:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) % 256])
    return bytes(out)


def decrypt_page(buf, pgno, ks):
    ps = len(buf)
    if ks is None:
        return bytes(buf)
    out = bytearray(buf)
    if pgno == 1:
        idx = list(range(0, 16)) + list(range(24, ps))
        src = list(range(0, 16)) + list(range(0, ps - 24))
        for i, k in zip(idx, src):
            out[i] ^= ks[k]
    else:
        for i in range(ps):
            out[i] ^= ks[i]
    return bytes(out)


def u32be(b, o):
    return int.from_bytes(b[o:o + 4], 'big')


def checksum(buf, s1, s2, little):
    order = 'little' if little else 'big'
    for o in range(0, len(buf), 8):
        s1 = (s1 + int.from_bytes(buf[o:o + 4], order) + s2) & 0xFFFFFFFF
        s2 = (s2 + int.from_bytes(buf[o + 4:o + 8], order) + s1) & 0xFFFFFFFF
    return s1, s2


def committed_frames(wal, ps):
    """Return (list of (pgno, stored data), db_size_at_last_commit, stats)."""
    stats = {'frames_total': 0, 'frames_valid': 0, 'commits': 0, 'break_at_frame': None}
    if len(wal) < 32:
        return [], None, stats
    magic = u32be(wal, 0)
    if magic not in (0x377F0682, 0x377F0683):
        return [], None, stats
    little = (magic == 0x377F0682)
    if u32be(wal, 8) != ps:
        raise ValueError('wal page size mismatch')
    s1, s2 = checksum(wal[:24], 0, 0, little)
    if (s1, s2) != (u32be(wal, 24), u32be(wal, 28)):
        stats['break_at_frame'] = 0
        return [], None, stats
    salt = wal[16:24]
    fsz = 24 + ps
    nframes = (len(wal) - 32) // fsz
    stats['frames_total'] = nframes
    pending, done, dbsize = [], [], None
    for n in range(nframes):
        o = 32 + n * fsz
        hdr, data = wal[o:o + 24], wal[o + 24:o + fsz]
        if hdr[8:16] != salt:
            stats['break_at_frame'] = n + 1; break
        s1, s2 = checksum(hdr[:8], s1, s2, little)
        s1, s2 = checksum(data, s1, s2, little)
        if (s1, s2) != (u32be(hdr, 16), u32be(hdr, 20)):
            stats['break_at_frame'] = n + 1; break
        stats['frames_valid'] += 1
        pending.append((u32be(hdr, 0), data))
        commit = u32be(hdr, 4)
        if commit:
            done += pending; pending = []; dbsize = commit; stats['commits'] += 1
    return done, dbsize, stats


def decrypt_fixture(folder, key):
    db = open(os.path.join(folder, 'mpenginedb.db'), 'rb').read()
    walp = os.path.join(folder, 'mpenginedb.db-wal')
    wal = open(walp, 'rb').read() if os.path.exists(walp) else b''
    ks = keystream(key, 65536) if key else None
    if len(db) < 100:
        raise ValueError('too small')
    ps = int.from_bytes(db[16:18], 'big')     # bytes 16..23 are plaintext even when encrypted
    if ps == 1:
        ps = 65536
    if ps < 512 or ps & (ps - 1) or len(db) % ps:
        raise ValueError('bad page size / file size: %r' % ps)
    ks = ks[:ps] if ks else None
    pages = {i + 1: decrypt_page(db[i * ps:(i + 1) * ps], i + 1, ks) for i in range(len(db) // ps)}
    if pages[1][:16] != b'SQLite format 3\x00':
        raise ValueError('header magic mismatch after decrypt')
    frames, dbsize, stats = committed_frames(wal, ps)
    for pg, data in frames:
        pages[pg] = decrypt_page(data, pg, ks)
    if dbsize is None:
        dbsize = len(db) // ps
    img = bytearray(b''.join(pages.get(i, bytes(ps)) for i in range(1, dbsize + 1)))
    img[18] = 1; img[19] = 1
    stats['db_pages'] = len(db) // ps
    stats['image_pages'] = dbsize
    return bytes(img), stats


def read_all(img):
    d = tempfile.mkdtemp(dir=HERE)
    p = os.path.join(d, 'img.db')
    try:
        open(p, 'wb').write(img)
        con = sqlite3.connect('file:%s?mode=ro' % p, uri=True)
        ic = con.execute('PRAGMA integrity_check').fetchone()[0]
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        out = {}
        for t in tables:
            cur = con.execute('SELECT * FROM "%s" ORDER BY ID' % t)
            names = [c[0] for c in cur.description]
            out[t] = [dict(zip(names, [v.hex() if isinstance(v, bytes) else v for v in r])) for r in cur]
        con.close()
        return ic, out
    finally:
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))
        os.rmdir(d)


def main():
    known = bytes.fromhex(open(os.path.join(HERE, 'known_key', 'key.txt')).read().strip())
    ok_all = True
    for name in ['known_key', 'random_key', 'plain', 'corrupt_wal', 'no_wal', 'junk']:
        folder = os.path.join(HERE, name)
        kp = os.path.join(folder, 'key.txt')
        key = None if name == 'plain' else (bytes.fromhex(open(kp).read().strip()) if os.path.exists(kp) else known)
        try:
            img, st = decrypt_fixture(folder, key)
        except Exception as e:
            res = 'REJECTED (%s)' % e
            good = name == 'junk'
            print('%-12s %s -> %s' % (name, res, 'PASS' if good else 'FAIL'))
            ok_all &= good
            continue
        if name == 'junk':
            print('%-12s unexpectedly decrypted -> FAIL' % name); ok_all = False; continue
        ic, rows = read_all(img)
        exp = json.load(open(os.path.join(folder, 'expected_rows.json'), encoding='utf-8'))
        match = rows == exp
        if name == 'random_key':
            ksf = os.path.join(folder, 'keystream_sha256.txt')
            match &= hashlib.sha256(keystream(key, 4096)).hexdigest() == open(ksf).read().strip()
        good = ic == 'ok' and match
        ok_all &= good
        print('%-12s integrity=%s rows_match=%s db_pages=%d image_pages=%d wal_frames=%d valid=%d commits=%d break=%s'
              % (name, ic, match, st['db_pages'], st['image_pages'], st['frames_total'], st['frames_valid'],
                 st['commits'], st['break_at_frame']))
        print('%-12s rows: %s' % ('', ', '.join('%s=%d' % (t, len(v)) for t, v in rows.items())))
        print('%-12s image sha256=%s -> %s' % ('', hashlib.sha256(img).hexdigest(), 'PASS' if good else 'FAIL'))
    print('ALL PASS' if ok_all else 'SOME FAILED')
    sys.exit(0 if ok_all else 1)


if __name__ == '__main__':
    main()
