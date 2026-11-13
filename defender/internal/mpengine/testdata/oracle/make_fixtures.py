#!/usr/bin/env python3
"""Generate test fixtures for an mpenginedb.db decryptor (stdlib only).

Fixture sets (each a subfolder of this script's directory):
  known_key/   encrypted with the known 1.1.26100.4 key, db + wal
  random_key/  bigger DB, encrypted with a seeded random key, db + wal
  plain/       same data as known_key, unencrypted
  corrupt_wal/ known_key with one byte flipped in the first frame of the last WAL commit
  no_wal/      known_key db only
  junk/        10000 random bytes
"""
import hashlib, json, os, random, shutil, sqlite3, struct, sys, tempfile, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
PS = 4096

KNOWN_KEY = bytes.fromhex(
    '1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54fa'
    'a21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cbce48e23d053'
    '71ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe'
    '3c8a775233557dde13a8b14087cc1bc8f10f6ecdd083a959cff84a9d1d50755e'
    '3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd029'
    '1771861a54b4c285a9a3db7aca6d224aeacd621db9f2a22ed1e9e11d75bed7dc'
    '0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429b'
    'a495676b8398db2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253')

ASR_GUID = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'

SCHEMA = {
    'RollingQueuesValues': 'ID INTEGER PRIMARY KEY, EntryTable TEXT, EntryKey TEXT, EntryValue TEXT, InsertTime INTEGER, ExpireTime INTEGER',
    'RollingQueuesTables': 'ID INTEGER PRIMARY KEY, Namespace TEXT, Name TEXT, Capacity INTEGER, TimeToLive INTEGER',
    'AttributePersistContext': 'ID INTEGER PRIMARY KEY, FilePath TEXT, Context TEXT, InsertTime INTEGER, ExpireTime INTEGER',
    'FileHashes': 'ID INTEGER PRIMARY KEY, InstanceTimeStamp INTEGER, VSN INTEGER, FileID INTEGER, USN INTEGER, SHA1 BLOB, MD5 BLOB, SHA256 BLOB, CTPH BLOB, LSHASH BLOB, LSHASHS BLOB, PartialCRC1 INTEGER, PartialCRC2 INTEGER, PartialCRC3 INTEGER, KCRC1 INTEGER, KCRC2 INTEGER, KCRC3 INTEGER, KCRC3n INTEGER',
    'BackupProcessInfo': 'ID INTEGER PRIMARY KEY, InstanceTimeStamp INTEGER, FilePath TEXT, FirstStartTime INTEGER, NextUSN INTEGER, AutomaticRemovalPolicy INTEGER, ImpactedCBPNameSpaces TEXT',
    'FileLowFiAsync': 'ID INTEGER PRIMARY KEY, InstanceTimeStamp INTEGER, FileName TEXT, SigSeq INTEGER, SigSha BLOB, SigIsSync INTEGER',
    'SQLiteGlobals': 'ID INTEGER PRIMARY KEY, Version INTEGER, Current INTEGER, LastUpdated TEXT',
    'AmsiFileCache': 'ID INTEGER PRIMARY KEY, ExpirationDate INTEGER, PersistId INTEGER, PersistIdBlob BLOB',
    'ProcessBlockHistory': 'ID INTEGER PRIMARY KEY, TimeStamp INTEGER, ProcessPath TEXT, TargetPath TEXT, RuleId BLOB, IsAudit INTEGER, Action INTEGER, ProcessTaintReason INTEGER, ProcessIntegrity INTEGER',
    'BmProcessInfo': 'ID INTEGER PRIMARY KEY, ProcessStartTime INTEGER, PID INTEGER, ImageFileName TEXT, CommandLineArgs TEXT, PPIDHash INTEGER, Flags INTEGER, MonitoringFlags_Flags INTEGER, HipsInjectionId BLOB, FolderGuardId BLOB, LsassReadMemId BLOB',
    'RansomwareDetections': 'ID INTEGER PRIMARY KEY, DetectionGuid BLOB, DetectionTS INTEGER, LkgTS INTEGER, ProvisionalRemedComplTS INTEGER, RemedComplTS INTEGER, InstanceTimeStamp INTEGER, NextUSN INTEGER, ImpactedCBPNameSpaces TEXT',
    'NetworkIpFirewallRules': 'ID INTEGER PRIMARY KEY, ExpiryTime INTEGER, Key TEXT, FirewallRuleName TEXT',
    'NetworkIpFirewallRulesOutgoing': 'ID INTEGER PRIMARY KEY, ExpiryTime INTEGER, Key TEXT, FirewallRuleName TEXT',
    'AtomicCounters': 'ID INTEGER PRIMARY KEY, InsertTime INTEGER, UpdateTime INTEGER, ExpireTime INTEGER, Namespace TEXT, Name TEXT, Count INTEGER, HighCount INTEGER',
    'FolderGuardPaths': 'ID INTEGER PRIMARY KEY, UserId TEXT, GUID BLOB, Path TEXT',
    'MetaInventoryIdentifiers': 'ID INTEGER PRIMARY KEY, Identifier TEXT, Kind INTEGER',
    'MetaInventoryIdentifierVulnerabilities': 'ID INTEGER PRIMARY KEY, Identifier TEXT, VulnerabilityId TEXT',
}


def ft(unix):
    return (int(unix) + 11644473600) * 10 ** 7


T0 = 1793520000          # 2026-11-01 00:00:00 UTC
DAY = 86400


def g(s):
    return uuid.UUID(s).bytes_le


def ctph(s):
    b = s.encode()
    return b + b'\x00' * (128 - len(b))


# ------------------------------------------------------------------ encryption

def rc4(key, n):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(n)
    for k in range(n):
        i = (i + 1) & 255; j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out[k] = S[(S[i] + S[j]) & 255]
    return bytes(out)


def xorb(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def enc_page(data, pgno, ks):
    assert len(data) == PS
    if pgno == 1:
        return xorb(data[:16], ks[:16]) + data[16:24] + xorb(data[24:], ks[:PS - 24])
    return xorb(data, ks)


def enc_db(db, ks):
    assert len(db) % PS == 0
    return b''.join(enc_page(db[i:i + PS], i // PS + 1, ks) for i in range(0, len(db), PS))


def wal_cksum(data, s0, s1, big):
    n = len(data) // 4
    v = struct.unpack(('>' if big else '<') + '%dI' % n, data)
    for i in range(0, n, 2):
        s0 = (s0 + v[i] + s1) & 0xFFFFFFFF
        s1 = (s1 + v[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def wal_frames(wal):
    out, off = [], 32
    while off + 24 + PS <= len(wal):
        out.append((off, wal[off:off + 24], wal[off + 24:off + 24 + PS]))
        off += 24 + PS
    return out


def rechain_wal(hdr, frames):
    """hdr: 32 bytes; frames: list of (24-byte header, page data). Recompute checksums over given bytes."""
    big = struct.unpack('>I', hdr[:4])[0] & 1
    out = bytearray(hdr[:24])
    s0, s1 = wal_cksum(bytes(hdr[:24]), 0, 0, big)
    out += struct.pack('>2I', s0, s1)
    for fh, data in frames:
        s0, s1 = wal_cksum(fh[:8], s0, s1, big)
        s0, s1 = wal_cksum(data, s0, s1, big)
        out += fh[:16] + struct.pack('>2I', s0, s1) + data
    return bytes(out)


def fix_salts(wal, salt1, salt2):
    """Replace SQLite's random WAL salts with fixed ones (for reproducible fixtures) and rechain."""
    hdr = bytearray(wal[:32]); hdr[16:24] = struct.pack('>2I', salt1, salt2)
    old = wal[16:24]
    frames = []
    for off, fh, data in wal_frames(wal):
        assert fh[8:16] == old
        frames.append((fh[:8] + bytes(hdr[16:24]) + fh[16:], data))
    return rechain_wal(bytes(hdr), frames)


def enc_wal(wal, ks):
    frames = []
    for off, fh, data in wal_frames(wal):
        pg = struct.unpack('>I', fh[:4])[0]
        frames.append((fh, enc_page(data, pg, ks)))
    return rechain_wal(wal[:32], frames)


# ------------------------------------------------------------------ data

def base_rows(rng):
    pid_ft = ft(T0 + 3 * DAY + 3600 * 9 + 17)
    pid2_ft = ft(T0 + 5 * DAY + 3600 * 14 + 2)
    rows = {}
    rows['RollingQueuesTables'] = [
        (1, None, 'Tech-pid:4312,ProcessStart:%d' % pid_ft, 64, 3600),
        (2, None, 'RecentThreatsOnMachine', 100, 2592000),
        (3, None, 'gPidsTable', 1024, 86400),
        (4, None, 'RQ_RecentExecDropped_x', 32, 604800),
        (5, 'BM', 'Tact-pid:4312,ProcessStart:%d' % pid_ft, 64, 3600),
    ]
    ev = lambda pf, img: json.dumps({"ProcessId": "pid:%s" % pf, "Process_Img": img}, separators=(',', ':'))
    rows['RollingQueuesValues'] = [
        (1, 'Tech-pid:4312,ProcessStart:%d' % pid_ft, 'T1547.001', ev('4312,ProcessStart:%d' % pid_ft, 'C:\\Windows\\System32\\rundll32.exe'), ft(T0 + 3 * DAY + 33000), ft(T0 + 3 * DAY + 36600)),
        (2, 'Tech-pid:4312,ProcessStart:%d' % pid_ft, 'T1059.001', ev('4312,ProcessStart:%d' % pid_ft, 'C:\\Windows\\System32\\rundll32.exe'), ft(T0 + 3 * DAY + 33010), ft(T0 + 3 * DAY + 36610)),
        (3, 'Tact-pid:4312,ProcessStart:%d' % pid_ft, 'TA0003', ev('4312,ProcessStart:%d' % pid_ft, 'C:\\Windows\\System32\\rundll32.exe'), ft(T0 + 3 * DAY + 33011), ft(T0 + 3 * DAY + 36611)),
        (4, 'RecentThreatsOnMachine', 'Behavior:Win32/Persistence.A', ev('4312,ProcessStart:%d' % pid_ft, 'C:\\Windows\\System32\\rundll32.exe'), ft(T0 + 3 * DAY + 33020), ft(T0 + 33 * DAY)),
        (5, 'gPidsTable', 'pid:7788,ProcessStart:%d' % pid2_ft, ev('7788,ProcessStart:%d' % pid2_ft, 'C:\\Users\\jörg\\Desktop\\файл.exe'), ft(T0 + 5 * DAY + 50402), ft(T0 + 6 * DAY + 50402)),
        (6, 'RQ_RecentExecDropped_x', 'C:\\Users\\jörg\\AppData\\Local\\Temp\\7zS1A2B\\setup.exe', None, ft(T0 + 6 * DAY), ft(T0 + 13 * DAY)),
    ]
    rows['AttributePersistContext'] = [
        (1, 'C:\\Users\\jörg\\Downloads\\invoice_2026.zip', 'NewlyCreatedZip', ft(T0 + 2 * DAY), ft(T0 + 32 * DAY)),
        (2, 'C:\\Program Files\\Vendor\\app\\version.dll', 'BM_IsPotentialSideLoad', ft(T0 + 2 * DAY + 60), ft(T0 + 32 * DAY)),
        (3, 'C:\\Users\\jörg\\Desktop\\файл.exe', 'NewPECreatedNoCert', ft(T0 + 5 * DAY), ft(T0 + 35 * DAY)),
        (4, 'C:\\Users\\jörg\\Desktop\\файл.exe', 'ExecutedPENoCert', ft(T0 + 5 * DAY + 50402), ft(T0 + 35 * DAY)),
        (5, 'AsrRuleStateChangeFor:' + ASR_GUID, '2', ft(T0 + DAY), ft(T0 + 366 * DAY)),
        (6, 'MpTamperProtectionState', 'off', ft(T0 + DAY + 5), ft(T0 + 366 * DAY)),
    ]
    rows['BackupProcessInfo'] = [
        (1, ft(T0 + 4 * DAY), 'C:\\Windows\\System32\\vssadmin.exe', ft(T0 + 4 * DAY - 10), 123456789, 1, 'CBP_NS_1'),
        (2, ft(T0 + 4 * DAY + 100), 'C:\\Program Files\\Backup\\agent.exe', 42, 987654321, 0, None),
    ]
    rows['FileLowFiAsync'] = [
        (1, ft(T0 + 7 * DAY), 'C:\\Users\\jörg\\Downloads\\tool.exe', 2147483647, hashlib.sha1(b'sig-1').digest(), 0),
        (2, ft(T0 + 7 * DAY + 5), 'C:\\Users\\Public\\x.dll', 1999, hashlib.sha1(b'sig-2').digest(), 1),
        (3, ft(T0 + 7 * DAY + 9), 'D:\\share\\payload.js', 77, hashlib.sha1(b'sig-3').digest(), 0),
    ]
    rows['SQLiteGlobals'] = [(1, 7, 1, '2026-10-30 08:12:00'), (2, 6, 0, '2025-03-14 11:00:00')]
    rows['AmsiFileCache'] = [
        (1, ft(T0 + 40 * DAY), -6148914691236517206, bytes(range(16))),
        (2, ft(T0 + 41 * DAY), 1234567890123, hashlib.md5(b'amsi').digest()),
    ]
    rows['ProcessBlockHistory'] = [
        (1, ft(T0 + 8 * DAY), 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'C:\\Users\\jörg\\AppData\\Roaming\\evil.dll', g(ASR_GUID), 0, 1, 0, 2),
        (2, ft(T0 + 8 * DAY + 30), 'C:\\Users\\jörg\\Desktop\\файл.exe', 'C:\\Windows\\System32\\lsass.exe', g('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'), 1, 2, 4, 1),
    ]
    rows['BmProcessInfo'] = [
        (1, pid_ft, 4312, 'C:\\Windows\\System32\\rundll32.exe', 'rundll32.exe C:\\Users\\jörg\\AppData\\Local\\a.dll,Start', 0x1122334455667788, 0x10, 0x200, g('0e5f2b3a-1c4d-4e6f-8a9b-0c1d2e3f4a5b'), g('6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e'), None),
        (2, pid2_ft, 7788, 'C:\\Users\\jörg\\Desktop\\файл.exe', '"C:\\Users\\jörg\\Desktop\\файл.exe" --silent', -42, 0, 1, None, None, g('aabbccdd-eeff-4011-8233-445566778899')),
    ]
    rows['RansomwareDetections'] = [
        (1, g('11111111-2222-4333-8444-555555555555'), ft(T0 + 9 * DAY), ft(T0 + 9 * DAY - 600), ft(T0 + 9 * DAY + 60), ft(T0 + 9 * DAY + 120), ft(T0 + 9 * DAY), 55555, 'CBP_NS_1;CBP_NS_2'),
        (2, g('66666666-7777-4888-9999-aaaaaaaaaaaa'), ft(T0 + 10 * DAY), 0, 0, 0, ft(T0 + 10 * DAY), 66666, None),
    ]
    rows['NetworkIpFirewallRules'] = [
        (1, ft(T0 + 12 * DAY), '203.0.113.7', 'MpBlockIn_203.0.113.7'),
        (2, ft(T0 + 12 * DAY + 1), '2001:db8::1', 'MpBlockIn_2001:db8::1'),
    ]
    rows['NetworkIpFirewallRulesOutgoing'] = [
        (1, ft(T0 + 12 * DAY + 2), '198.51.100.23', 'MpBlockOut_198.51.100.23'),
        (2, ft(T0 + 12 * DAY + 3), '192.0.2.200', 'MpBlockOut_192.0.2.200'),
    ]
    rows['AtomicCounters'] = [
        (1, ft(T0 + DAY), ft(T0 + 9 * DAY), ft(T0 + 31 * DAY), 'BM', 'ProcessCreateCount', 1532, 1600),
        (2, ft(T0 + DAY), ft(T0 + 9 * DAY), ft(T0 + 31 * DAY), None, 'AsrBlocks', 3, 3),
        (3, ft(T0 + 2 * DAY), ft(T0 + 2 * DAY), ft(T0 + 3 * DAY), 'Net', 'FwRuleCount', 4, 10),
    ]
    rows['FolderGuardPaths'] = [
        (1, 'S-1-5-21-1004336348-1177238915-682003330-1001', g('f1a2b3c4-d5e6-4f70-8192-a3b4c5d6e7f8'), 'C:\\Users\\jörg\\Documents'),
        (2, 'S-1-5-21-1004336348-1177238915-682003330-1001', g('0a0b0c0d-0e0f-4011-a213-141516171819'), 'C:\\Users\\jörg\\Pictures\\Фото'),
    ]
    rows['MetaInventoryIdentifiers'] = [
        (1, 'cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*', 1),
        (2, 'pkg:generic/openssl@3.0.1', 2),
    ]
    rows['MetaInventoryIdentifierVulnerabilities'] = [
        (1, 'cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*', 'CVE-2024-11477'),
        (2, 'pkg:generic/openssl@3.0.1', 'CVE-2022-3602'),
        (3, 'pkg:generic/openssl@3.0.1', 'CVE-2022-3786'),
    ]
    return rows


def filehash_row(i, rng, sources):
    content = 'mpenginedb-fixture-file-%d' % i
    b = content.encode()
    md5, sha1, sha256 = hashlib.md5(b).digest(), hashlib.sha1(b).digest(), hashlib.sha256(b).digest()
    sources[i] = content
    seq, entry = rng.randrange(1, 0x7FFF), rng.randrange(1, 1 << 40)
    def crc():
        return rng.randrange(-(1 << 31), 1 << 31)
    return (i, ft(T0 + rng.randrange(0, 12 * DAY)), rng.randrange(0, 1 << 32), (seq << 48) | entry,
            rng.randrange(0, 1 << 40),
            md5,            # SHA1 column holds the 16-byte MD5 (Defender swaps them)
            sha1,           # MD5 column holds the 20-byte SHA-1
            sha256,
            ctph('3:%s:%s' % (hashlib.sha1(b + b'c').hexdigest()[:22], hashlib.md5(b).hexdigest()[:10])),
            hashlib.sha256(b + b'ls').digest()[:rng.choice((8, 16))] if i % 3 else None,
            None if i % 4 else hashlib.md5(b + b'lss').digest(),
            crc(), crc(), crc(), crc(), crc(), -abs(crc()) - 1, crc())


def ins(c, table, row):
    c.execute('INSERT INTO %s VALUES (%s)' % (table, ','.join('?' * len(row))), row)


def read_with_wal(db_bytes, wal_bytes):
    """Open a throwaway copy of plaintext db (+wal) with sqlite3; integrity_check; return {table: [row dicts by ID]}."""
    d = tempfile.mkdtemp(dir=HERE)
    try:
        p = os.path.join(d, 'x.db')
        open(p, 'wb').write(db_bytes)
        if wal_bytes is not None:
            open(p + '-wal', 'wb').write(wal_bytes)
        con = sqlite3.connect(p)
        ok = con.execute('PRAGMA integrity_check').fetchone()[0]
        assert ok == 'ok', ok
        out = {}
        for t in SCHEMA:
            cur = con.execute('SELECT * FROM %s ORDER BY ID' % t)
            cols = [x[0] for x in cur.description]
            out[t] = [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in zip(cols, r)} for r in cur]
        con.close()
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def build(n_hashes, delete_mode, seed):
    """Build a plaintext DB+WAL. Returns dict(db, wal, sources, commits_info)."""
    d = tempfile.mkdtemp(dir=HERE)
    try:
        return _build(d, n_hashes, delete_mode, seed)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _build(d, n_hashes, delete_mode, seed):
    rng = random.Random(seed)
    p = os.path.join(d, 'mpenginedb.db')
    con = sqlite3.connect(p, isolation_level=None)
    con.execute('PRAGMA page_size=%d' % PS)
    assert con.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
    con.execute('PRAGMA wal_autocheckpoint=0')
    c = con.cursor()
    c.execute('BEGIN')
    for t, cols in SCHEMA.items():
        c.execute('CREATE TABLE %s (%s)' % (t, cols))
    for t, rs in base_rows(rng).items():
        for r in rs:
            ins(c, t, r)
    sources = {}
    for i in range(1, n_hashes + 1):
        ins(c, 'FileHashes', filehash_row(i, rng, sources))
    c.execute('COMMIT')
    c.execute('BEGIN')
    ids = list(range(1, n_hashes + 1))
    if delete_mode == 'alternate':
        dels = [i for i in ids if i % 2 == 0]
    else:
        dels = rng.sample(ids, int(len(ids) * 0.4))
    for i in dels:
        c.execute('DELETE FROM FileHashes WHERE ID=?', (i,))
        sources.pop(i)
    c.execute('COMMIT')
    r = c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
    assert r[0] == 0, r
    assert os.path.getsize(p + '-wal') == 0

    # ---- WAL-only transactions
    nxt = n_hashes + 1
    pid3_ft = ft(T0 + 11 * DAY + 777)
    # txn 1: inserts in several tables
    c.execute('BEGIN')
    ins(c, 'RollingQueuesValues', (7, 'Tech-pid:9120,ProcessStart:%d' % pid3_ft, 'T1003.001',
        json.dumps({"ProcessId": "pid:9120,ProcessStart:%d" % pid3_ft, "Process_Img": "C:\\Users\\jörg\\AppData\\Local\\Temp\\procdump64.exe"}, separators=(',', ':')),
        ft(T0 + 11 * DAY + 800), ft(T0 + 11 * DAY + 4400)))
    ins(c, 'RollingQueuesTables', (6, None, 'Tech-pid:9120,ProcessStart:%d' % pid3_ft, 64, 3600))
    ins(c, 'ProcessBlockHistory', (3, ft(T0 + 11 * DAY + 801), 'C:\\Users\\jörg\\AppData\\Local\\Temp\\procdump64.exe',
        'C:\\Windows\\System32\\lsass.exe', g('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'), 0, 1, 8, 2))
    ins(c, 'BmProcessInfo', (3, pid3_ft, 9120, 'C:\\Users\\jörg\\AppData\\Local\\Temp\\procdump64.exe',
        'procdump64.exe -ma lsass.exe out.dmp', 0x7FEDCBA987654321, 0x40, 0x1, None, None, g('aabbccdd-eeff-4011-8233-445566778899')))
    for k in range(5):
        ins(c, 'FileHashes', filehash_row(nxt, rng, sources)); nxt += 1
    c.execute('COMMIT')
    # txn 2: update a row
    c.execute('BEGIN')
    c.execute('UPDATE AtomicCounters SET Count=Count+1, UpdateTime=? WHERE ID=2', (ft(T0 + 11 * DAY + 801),))
    c.execute("UPDATE SQLiteGlobals SET LastUpdated='2026-11-12 09:30:00' WHERE ID=1")
    c.execute('COMMIT')
    # txn 3: delete a row
    c.execute('BEGIN')
    c.execute('DELETE FROM FileLowFiAsync WHERE ID=2')
    c.execute('DELETE FROM AttributePersistContext WHERE ID=1')
    c.execute('COMMIT')
    # txn 4 (last): new vuln + a big batch of FileHashes rows that grows the file (touches page 1 header)
    c.execute('BEGIN')
    ins(c, 'MetaInventoryIdentifierVulnerabilities', (4, 'pkg:generic/openssl@3.0.1', 'CVE-2023-0286'))
    ins(c, 'FolderGuardPaths', (3, 'S-1-5-18', g('12345678-9abc-4def-8123-456789abcdef'), 'D:\\Backups'))
    for k in range(60):
        ins(c, 'FileHashes', filehash_row(nxt, rng, sources)); nxt += 1
    c.execute('COMMIT')

    db = open(p, 'rb').read()
    wal = open(p + '-wal', 'rb').read()
    con.close()
    wal = fix_salts(wal, 0x5A17A000 + seed, 0x0BADC0DE ^ seed)
    return dict(db=db, wal=wal, sources=sources)


def commit_frames(wal):
    """indices (0-based) of commit frames in a plaintext WAL with valid chain (no validation)."""
    return [i for i, (off, fh, data) in enumerate(wal_frames(wal)) if struct.unpack('>I', fh[4:8])[0]]


def write(dirname, files):
    d = os.path.join(HERE, dirname)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for name, content in files.items():
        mode = 'wb' if isinstance(content, bytes) else 'w'
        with open(os.path.join(d, name), mode, **({} if mode == 'wb' else {'encoding': 'utf-8'})) as f:
            f.write(content)


def jdump(o):
    return json.dumps(o, indent=1, ensure_ascii=False, sort_keys=False) + '\n'


def main():
    ks_known = rc4(KNOWN_KEY, PS)

    # ---- known_key / plain / no_wal / corrupt_wal
    b = build(200, 'alternate', 1)
    db, wal = b['db'], b['wal']
    assert len(db) % PS == 0 and db[18] == 2 and db[19] == 2
    exp_full = read_with_wal(db, wal)
    exp_nowal = read_with_wal(db, None)
    hs = jdump({str(k): v for k, v in sorted(b['sources'].items())})
    srcs_note = ('FileHashes: column SHA1 = md5(content), column MD5 = sha1(content), SHA256 = sha256(content); '
                 'content per ID in hash_sources.json')

    edb, ewal = enc_db(db, ks_known), enc_wal(wal, ks_known)
    write('known_key', {'mpenginedb.db': edb, 'mpenginedb.db-wal': ewal, 'expected_rows.json': jdump(exp_full),
                        'hash_sources.json': hs, 'key.txt': KNOWN_KEY.hex() + '\n',
                        'keystream_sha256.txt': hashlib.sha256(ks_known).hexdigest() + '\n'})
    write('plain', {'mpenginedb.db': db, 'mpenginedb.db-wal': wal, 'expected_rows.json': jdump(exp_full),
                    'hash_sources.json': hs})
    write('no_wal', {'mpenginedb.db': edb, 'expected_rows.json': jdump(exp_nowal), 'hash_sources.json': hs,
                     'key.txt': KNOWN_KEY.hex() + '\n'})

    cf = commit_frames(wal)
    assert len(cf) >= 4, cf
    first_last = cf[-2] + 1           # first frame of last committed txn
    frames = wal_frames(wal)
    off = frames[first_last][0]
    exp_corrupt = read_with_wal(db, wal[:off])
    cw = bytearray(ewal)
    flip_at = off + 24 + 100
    cw[flip_at] ^= 0x5A
    write('corrupt_wal', {'mpenginedb.db': edb, 'mpenginedb.db-wal': bytes(cw), 'expected_rows.json': jdump(exp_corrupt),
                          'hash_sources.json': hs, 'key.txt': KNOWN_KEY.hex() + '\n',
                          'corruption.txt': 'flipped byte at WAL offset %d (frame #%d, 1-based; first frame of last commit), xor 0x5a\n'
                          % (flip_at, first_last + 1)})

    # ---- random_key
    rk = random.Random(0xDEFE4DE5)
    key = bytes(rk.randrange(256) for _ in range(256))
    ks = rc4(key, PS)
    b2 = build(4000, 'random40', 2)
    exp2 = read_with_wal(b2['db'], b2['wal'])
    write('random_key', {'mpenginedb.db': enc_db(b2['db'], ks), 'mpenginedb.db-wal': enc_wal(b2['wal'], ks),
                         'expected_rows.json': jdump(exp2), 'key.txt': key.hex() + '\n',
                         'keystream_sha256.txt': hashlib.sha256(ks).hexdigest() + '\n',
                         'hash_sources.json': jdump({str(k): v for k, v in sorted(b2['sources'].items())})})

    # ---- junk
    write('junk', {'mpenginedb.db': random.Random(7).randbytes(10000)})
    print('note:', srcs_note)
    print('done')


if __name__ == '__main__':
    main()
