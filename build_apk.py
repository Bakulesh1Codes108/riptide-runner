#!/usr/bin/env python3
"""Build a signed Android APK (WebView wrapper around assets/index.html) without the Android SDK.
Writes: classes.dex (hand-assembled), binary AndroidManifest.xml, resources.arsc (app icon),
then zips, aligns and signs with APK Signature Scheme v2."""
import struct, hashlib, zlib, io, sys, os, datetime
from PIL import Image, ImageDraw, ImageFilter

PKG = "com.riptide.runner"
CLS = "Lcom/riptide/runner/MainActivity;"
APP_NAME = "Riptide Runner"
u8 = lambda v: struct.pack('<B', v)
u16 = lambda v: struct.pack('<H', v)
u32 = lambda v: struct.pack('<I', v & 0xffffffff)
u64 = lambda v: struct.pack('<Q', v)

def uleb(v):
    out = b''
    while True:
        b = v & 0x7f; v >>= 7
        if v: out += bytes([b | 0x80])
        else: return out + bytes([b])

# ------------------------------------------------------------------ DEX
def build_dex():
    T = dict(act="Landroid/app/Activity;", ctx="Landroid/content/Context;", bundle="Landroid/os/Bundle;",
             view="Landroid/view/View;", win="Landroid/view/Window;", ws="Landroid/webkit/WebSettings;",
             wv="Landroid/webkit/WebView;", me=CLS, str="Ljava/lang/String;", V="V", Z="Z", I="I")
    URL = "file:///android_asset/index.html"
    # protos: (shorty, return, params)
    protos_l = [("V", "V", ()), ("L", T['win'], ()), ("L", T['ws'], ()), ("VL", "V", (T['bundle'],)),
                ("VL", "V", (T['ctx'],)), ("VL", "V", (T['view'],)), ("VL", "V", (T['str'],)),
                ("VZ", "V", ("Z",)), ("VI", "V", ("I",))]
    # methods: key -> (class, name, proto)
    M = {
        'act_init': (T['act'], "<init>", ("V", "V", ())),
        'act_onCreate': (T['act'], "onCreate", ("VL", "V", (T['bundle'],))),
        'act_getWindow': (T['act'], "getWindow", ("L", T['win'], ())),
        'act_setContentView': (T['act'], "setContentView", ("VL", "V", (T['view'],))),
        'view_sysui': (T['view'], "setSystemUiVisibility", ("VI", "V", ("I",))),
        'win_addFlags': (T['win'], "addFlags", ("VI", "V", ("I",))),
        'ws_js': (T['ws'], "setJavaScriptEnabled", ("VZ", "V", ("Z",))),
        'ws_dom': (T['ws'], "setDomStorageEnabled", ("VZ", "V", ("Z",))),
        'ws_media': (T['ws'], "setMediaPlaybackRequiresUserGesture", ("VZ", "V", ("Z",))),
        'wv_init': (T['wv'], "<init>", ("VL", "V", (T['ctx'],))),
        'wv_getSettings': (T['wv'], "getSettings", ("L", T['ws'], ())),
        'wv_loadUrl': (T['wv'], "loadUrl", ("VL", "V", (T['str'],))),
        'me_init': (T['me'], "<init>", ("V", "V", ())),
        'me_onCreate': (T['me'], "onCreate", ("VL", "V", (T['bundle'],))),
    }
    strings = set(T.values()) | {URL}
    for s, r, p in protos_l: strings.add(s)
    for c, n, pr in M.values(): strings.add(n)
    def mutf8_key(s):  # sort by UTF-16 code units
        return [ord(ch) for ch in s]
    strings = sorted(strings, key=mutf8_key)
    sidx = {s: i for i, s in enumerate(strings)}
    types = sorted(set(T.values()), key=lambda t: sidx[t])
    tidx = {t: i for i, t in enumerate(types)}
    protos = sorted(set(protos_l), key=lambda p: (tidx[p[1]], [tidx[x] for x in p[2]]))
    pidx = {p: i for i, p in enumerate(protos)}
    meths = sorted(M.items(), key=lambda kv: (tidx[kv[1][0]], sidx[kv[1][1]], pidx[kv[1][2]]))
    midx = {k: i for i, (k, v) in enumerate(meths)}

    def i35c(op, regs, idx):
        r = list(regs) + [0] * (5 - len(regs))
        C, D, E, F, G = r
        return [op | (G << 8) | (len(regs) << 12), idx, C | (D << 4) | (E << 8) | (F << 12)]
    def c4(reg, lit): return [0x12 | (((lit & 0xf) << 4 | reg) << 8)]
    def c16(reg, lit): return [0x13 | (reg << 8), lit & 0xffff]
    mro = lambda reg: [0x0c | (reg << 8)]
    ret = [0x000e]
    # <init>: registers=1 (this=v0)
    init_code = i35c(0x70, [0], midx['act_init']) + ret
    # onCreate: v0..v3 locals, v4=this, v5=bundle
    oc = []
    oc += i35c(0x6f, [4, 5], midx['act_onCreate'])
    oc += i35c(0x6e, [4], midx['act_getWindow']) + mro(0)
    oc += c16(1, 0x480) + i35c(0x6e, [0, 1], midx['win_addFlags'])
    oc += [0x22 | (0 << 8), tidx[T['wv']]]
    oc += i35c(0x70, [0, 4], midx['wv_init'])
    oc += i35c(0x6e, [0], midx['wv_getSettings']) + mro(1)
    oc += c4(2, 1)
    oc += i35c(0x6e, [1, 2], midx['ws_js'])
    oc += i35c(0x6e, [1, 2], midx['ws_dom'])
    oc += c4(3, 0)
    oc += i35c(0x6e, [1, 3], midx['ws_media'])
    oc += c16(1, 0x1706) + i35c(0x6e, [0, 1], midx['view_sysui'])
    oc += [0x1a | (3 << 8), sidx[URL]]
    oc += i35c(0x6e, [0, 3], midx['wv_loadUrl'])
    oc += i35c(0x6e, [4, 0], midx['act_setContentView'])
    oc += ret
    codes = [(1, 1, 1, init_code), (6, 2, 2, oc)]

    HDR = 0x70
    off = HDR
    string_ids_off = off; off += 4 * len(strings)
    type_ids_off = off; off += 4 * len(types)
    proto_ids_off = off; off += 12 * len(protos)
    method_ids_off = off; off += 8 * len(meths)
    class_defs_off = off; off += 32
    data_off = off
    data = bytearray()
    def align(n=4):
        while (data_off + len(data)) % n: data.append(0)
    # code items
    align(); code_items_off = data_off + len(data); code_offs = []
    for regs, ins, outs, insns in codes:
        align(); code_offs.append(data_off + len(data))
        data += u16(regs) + u16(ins) + u16(outs) + u16(0) + u32(0) + u32(len(insns))
        for w in insns: data += u16(w)
    # type lists
    align(); type_lists_off = data_off + len(data); tl_off = {}
    for p in protos:
        if p[2] and p[2] not in tl_off:
            align(); tl_off[p[2]] = data_off + len(data)
            data += u32(len(p[2])) + b''.join(u16(tidx[x]) for x in p[2])
    n_type_lists = len(tl_off)
    # string data
    string_data_off = data_off + len(data); sd_off = []
    for s in strings:
        sd_off.append(data_off + len(data))
        data += uleb(len(s)) + s.encode('utf-8') + b'\0'
    # class data
    class_data_off = data_off + len(data)
    data += uleb(0) + uleb(0) + uleb(1) + uleb(1)
    data += uleb(midx['me_init']) + uleb(0x10001) + uleb(code_offs[0])
    data += uleb(midx['me_onCreate']) + uleb(0x4) + uleb(code_offs[1])
    # map list
    align(); map_off = data_off + len(data)
    items = [(0x0000, 1, 0), (0x0001, len(strings), string_ids_off), (0x0002, len(types), type_ids_off),
             (0x0003, len(protos), proto_ids_off), (0x0005, len(meths), method_ids_off), (0x0006, 1, class_defs_off),
             (0x2001, len(codes), code_items_off), (0x1001, n_type_lists, type_lists_off),
             (0x2002, len(strings), string_data_off), (0x2000, 1, class_data_off), (0x1000, 1, map_off)]
    data += u32(len(items))
    for t, n, o in items: data += u16(t) + u16(0) + u32(n) + u32(o)
    align()
    body = bytearray()
    for o in sd_off: body += u32(o)
    for t in types: body += u32(sidx[t])
    for p in protos: body += u32(sidx[p[0]]) + u32(tidx[p[1]]) + u32(tl_off[p[2]] if p[2] else 0)
    for k, (c, n, pr) in meths: body += u16(tidx[c]) + u16(pidx[pr]) + u32(sidx[n])
    body += u32(tidx[T['me']]) + u32(0x1) + u32(tidx[T['act']]) + u32(0) + u32(0xffffffff) + u32(0) + u32(class_data_off) + u32(0)
    assert HDR + len(body) == data_off
    file_size = data_off + len(data)
    hdr = bytearray(b'dex\n035\0' + b'\0' * 4 + b'\0' * 20)
    hdr += u32(file_size) + u32(HDR) + u32(0x12345678) + u32(0) + u32(0) + u32(map_off)
    hdr += u32(len(strings)) + u32(string_ids_off) + u32(len(types)) + u32(type_ids_off)
    hdr += u32(len(protos)) + u32(proto_ids_off) + u32(0) + u32(0) + u32(len(meths)) + u32(method_ids_off)
    hdr += u32(1) + u32(class_defs_off) + u32(len(data)) + u32(data_off)
    assert len(hdr) == HDR
    dex = bytearray(hdr + body + data)
    dex[12:32] = hashlib.sha1(dex[32:]).digest()
    dex[8:12] = u32(zlib.adler32(bytes(dex[12:])))
    return bytes(dex)

# ------------------------------------------------------------------ string pool (UTF-16)
def string_pool(strs):
    offs, blob = [], bytearray()
    for s in strs:
        offs.append(len(blob)); e = s.encode('utf-16-le')
        blob += u16(len(s)) + e + b'\0\0'
    while len(blob) % 4: blob += b'\0'
    hdr_size = 28; start = hdr_size + 4 * len(strs)
    size = start + len(blob)
    return u16(0x0001) + u16(hdr_size) + u32(size) + u32(len(strs)) + u32(0) + u32(0) + u32(start) + u32(0) + b''.join(u32(o) for o in offs) + bytes(blob)

# ------------------------------------------------------------------ binary AndroidManifest.xml
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR = {'theme': 0x01010000, 'label': 0x01010001, 'icon': 0x01010002, 'name': 0x01010003, 'exported': 0x01010010,
        'screenOrientation': 0x0101001e, 'configChanges': 0x0101001f, 'minSdkVersion': 0x0101020c,
        'versionCode': 0x0101021b, 'versionName': 0x0101021c, 'targetSdkVersion': 0x01010270, 'hardwareAccelerated': 0x010102d3}
STR, INT_DEC, INT_HEX, BOOL, REF = 0x03, 0x10, 0x11, 0x12, 0x01
def build_manifest():
    tree = ('manifest', [('versionCode', INT_DEC, 1), ('versionName', STR, '1.0'), ('package', STR, PKG)], [
        ('uses-sdk', [('minSdkVersion', INT_DEC, 24), ('targetSdkVersion', INT_DEC, 34)], []),
        ('uses-permission', [('name', STR, 'android.permission.VIBRATE')], []),
        ('application', [('theme', REF, 0x0103000a), ('label', STR, APP_NAME), ('icon', REF, 0x7f010000), ('hardwareAccelerated', BOOL, 1)], [
            ('activity', [('name', STR, PKG + '.MainActivity'), ('exported', BOOL, 1), ('screenOrientation', INT_DEC, 1), ('configChanges', INT_HEX, 0x4a0)], [
                ('intent-filter', [], [
                    ('action', [('name', STR, 'android.intent.action.MAIN')], []),
                    ('category', [('name', STR, 'android.intent.category.LAUNCHER')], [])])])])])
    attr_names = list(ATTR.keys())
    strs = list(attr_names)
    def add(s):
        if s not in strs: strs.append(s)
    add('android'); add(ANDROID_NS)
    def walk(n):
        add(n[0])
        for a, t, v in n[1]:
            add(a)
            if t == STR: add(v)
        for c in n[2]: walk(c)
    walk(tree)
    si = {s: i for i, s in enumerate(strs)}
    body = bytearray()
    body += u16(0x0100) + u16(16) + u32(24) + u32(1) + u32(0xffffffff) + u32(si['android']) + u32(si[ANDROID_NS])
    def emit(n):
        tag, attrs, kids = n
        attrs = sorted(attrs, key=lambda a: (ATTR.get(a[0], 0xffffffff)))
        ab = bytearray()
        for a, t, v in attrs:
            ns = si[ANDROID_NS] if a in ATTR else 0xffffffff
            raw = si[v] if t == STR else 0xffffffff
            data = si[v] if t == STR else (0xffffffff if (t == BOOL and v) else v)
            ab += u32(ns) + u32(si[a]) + u32(raw) + u16(8) + u8(0) + u8(t) + u32(data)
        body.extend(u16(0x0102) + u16(16) + u32(36 + len(ab)) + u32(1) + u32(0xffffffff) + u32(0xffffffff) + u32(si[tag])
                    + u16(20) + u16(20) + u16(len(attrs)) + u16(0) + u16(0) + u16(0) + ab)
        for c in kids: emit(c)
        body.extend(u16(0x0103) + u16(16) + u32(24) + u32(1) + u32(0xffffffff) + u32(0xffffffff) + u32(si[tag]))
    emit(tree)
    body += u16(0x0101) + u16(16) + u32(24) + u32(1) + u32(0xffffffff) + u32(si['android']) + u32(si[ANDROID_NS])
    pool = string_pool(strs)
    resmap = u16(0x0180) + u16(8) + u32(8 + 4 * len(attr_names)) + b''.join(u32(ATTR[a]) for a in attr_names)
    total = 8 + len(pool) + len(resmap) + len(body)
    return u16(0x0003) + u16(8) + u32(total) + pool + resmap + bytes(body)

# ------------------------------------------------------------------ resources.arsc with one drawable
def build_arsc():
    gpool = string_pool(["res/drawable/icon.png"])
    tpool = string_pool(["drawable"]); kpool = string_pool(["icon"])
    spec = u16(0x0202) + u16(16) + u32(20) + u8(1) + u8(0) + u16(0) + u32(1) + u32(0)
    config = u32(64) + b'\0' * 60
    hdr_size = 20 + len(config); entries_start = hdr_size + 4
    entry = u16(8) + u16(0) + u32(0) + u16(8) + u8(0) + u8(0x03) + u32(0)
    ttype = u16(0x0201) + u16(hdr_size) + u32(entries_start + len(entry)) + u8(1) + u8(0) + u16(0) + u32(1) + u32(entries_start) + config + u32(0) + entry
    name = PKG.encode('utf-16-le'); name = name + b'\0' * (256 - len(name))
    pkg_hdr = 288
    pkg_body = tpool + kpool + spec + ttype
    pkg = u16(0x0200) + u16(pkg_hdr) + u32(pkg_hdr + len(pkg_body)) + u32(0x7f) + name + u32(pkg_hdr) + u32(1) + u32(pkg_hdr + len(tpool)) + u32(1) + u32(0) + pkg_body
    return u16(0x0002) + u16(12) + u32(12 + len(gpool) + len(pkg)) + u32(1) + gpool + pkg

# ------------------------------------------------------------------ icon
def build_icon():
    S = 512
    im = Image.new('RGB', (S, S))
    d = ImageDraw.Draw(im)
    for y in range(S):
        t = y / S
        d.line([(0, y), (S, y)], fill=(int(150 + 60 * t), int(158 + 40 * t), int(166 + 20 * t)) if y < S * .55 else (int(28 + 20 * (1 - t)), int(36 + 18 * (1 - t)), int(38 + 16 * (1 - t))))
    # canyon walls
    d.polygon([(0, S * .25), (S * .22, S * .3), (S * .38, S * .52), (S * .42, S * .56), (0, S * .62)], fill=(150, 92, 62))
    d.polygon([(S, S * .2), (S * .74, S * .3), (S * .6, S * .5), (S * .56, S * .56), (S, S * .62)], fill=(166, 104, 70))
    d.rectangle([0, S * .55, S, S * .6], fill=(212, 200, 182))
    # jet ski hood + pad (lime) in POV
    d.ellipse([S * .14, S * .66, S * .86, S * 1.2], fill=(20, 22, 24))
    d.ellipse([S * .24, S * .6, S * .76, S * .88], fill=(196, 236, 30))
    d.ellipse([S * .41, S * .63, S * .59, S * .77], fill=(28, 32, 34))
    d.ellipse([S * .45, S * .665, S * .55, S * .735], fill=(220, 226, 230))
    d.rounded_rectangle([S * .27, S * .8, S * .73, S * 1.02], radius=40, fill=(204, 244, 36))
    im = im.resize((192, 192), Image.LANCZOS)
    b = io.BytesIO(); im.save(b, 'PNG', optimize=True); return b.getvalue()

# ------------------------------------------------------------------ zip + v2 signing
def dostime():
    t = datetime.datetime(2026, 10, 24, 12, 0, 0)
    return ((t.hour << 11) | (t.minute << 5) | (t.second // 2)), (((t.year - 1980) << 9) | (t.month << 5) | t.day)
def build_zip(entries):
    out = bytearray(); cd = bytearray(); tm, dt = dostime()
    for name, data, store, align in entries:
        nb = name.encode(); crc = zlib.crc32(data) & 0xffffffff
        if store: comp, method = data, 0
        else:
            co = zlib.compressobj(9, zlib.DEFLATED, -15); comp = co.compress(data) + co.flush(); method = 8
        off = len(out); extra = b''
        if store and align:
            pad = (-(off + 30 + len(nb))) % align; extra = b'\0' * pad
        out += struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, 0, method, tm, dt, crc, len(comp), len(data), len(nb), len(extra)) + nb + extra + comp
        cd += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, 0, method, tm, dt, crc, len(comp), len(data), len(nb), 0, 0, 0, 0, 0, off) + nb
    cd_off = len(out)
    eocd = struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, len(entries), len(entries), len(cd), cd_off, 0)
    return bytes(out), bytes(cd), eocd

def sign_v2(contents, cd, eocd, key, cert_der):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    lp = lambda b: u32(len(b)) + b
    def chunks(b):
        return [b[i:i + 1048576] for i in range(0, len(b), 1048576)] if b else []
    allc = chunks(contents) + chunks(cd) + chunks(eocd)
    top = hashlib.sha256(b'\x5a' + u32(len(allc)) + b''.join(hashlib.sha256(b'\xa5' + u32(len(c)) + c).digest() for c in allc)).digest()
    ALG = 0x0103
    signed_data = lp(lp(u32(ALG) + lp(top))) + lp(lp(cert_der)) + lp(b'')
    sig = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed_data) + lp(lp(u32(ALG) + lp(sig))) + lp(pub)
    value = lp(lp(signer))
    pair = u64(4 + len(value)) + u32(0x7109871a) + value
    size = len(pair) + 8 + 16
    block = u64(size) + pair + u64(size) + b'APK Sig Block 42'
    new_eocd = eocd[:16] + u32(len(contents) + len(block)) + eocd[20:]
    return contents + block + cd + new_eocd

def get_key(path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    if os.path.exists(path):
        key = serialization.load_pem_private_key(open(path, 'rb').read(), None)
        cert = x509.load_pem_x509_certificate(open(path + '.crt', 'rb').read())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, APP_NAME), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Riptide')])
        now = datetime.datetime(2026, 1, 1)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365 * 30))
                .sign(key, hashes.SHA256()))
        open(path, 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(path + '.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
    from cryptography.hazmat.primitives import serialization as ser
    return key, cert.public_bytes(ser.Encoding.DER)

if __name__ == '__main__':
    html_path, out_path, key_path = sys.argv[1], sys.argv[2], sys.argv[3]
    entries = [("AndroidManifest.xml", build_manifest(), False, 0), ("classes.dex", build_dex(), False, 0),
               ("resources.arsc", build_arsc(), True, 4), ("res/drawable/icon.png", build_icon(), True, 4),
               ("assets/index.html", open(html_path, 'rb').read(), False, 0)]
    contents, cd, eocd = build_zip(entries)
    key, cert = get_key(key_path)
    apk = sign_v2(contents, cd, eocd, key, cert)
    open(out_path, 'wb').write(apk)
    for n, d, *_ in entries: open('/tmp/claude-0/-home-claude/1b26806f-eb61-5658-be23-5a4ec6f9076f/scratchpad/' + n.replace('/', '_'), 'wb').write(d)
    print('wrote', out_path, len(apk), 'bytes')
