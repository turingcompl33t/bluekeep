# Scanner.py
# CVE-2019-0708 "Bluekeep" Vulnerability Scanner.
#
# Usage: Scanner.py <Host> [-v]
#
# Arguments:
#   Host - IP address of the host to scan
#   -v   - Enable verbose output (optional)
#
# Confirmed Targets:
#   - Windows 7
#   - Windows Server 2008; Windows Server 2008 R2
#   - Windows Server 2003 
#   - Windows XP
#
# References:
# - https://www.seebug.org/vuldb/ssvid-97954
# - https://github.com/zerosum0x0/CVE-2019-0708 
# - https://github.com/fenixns/CVE-2019-0708

import sys
import socket
import struct
import random
import base64
import hashlib
import binascii
import argparse

# -----------------------------------------------------------------------------
# Entry Point

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", metavar="Host", help="The IP address of the host to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    args = parser.parse_args()

    target_ip = args.host
    verbose   = args.verbose

    log("Scanning target at {}".format(target_ip))

    rdp_ctx = RDP()
    res = rdp_ctx.run_scan(target_ip, 3389, verbose)

    log("Scan complete for target at {}:".format(target_ip))
    if res:
        log("Target VULNERABLE")
    else:
        log("Target NOT VULNERABLE")

    sys.exit(0)

# -----------------------------------------------------------------------------
# Primary Helper Functions

def create_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(10)
    sock.connect((ip, port))

    return sock

def fingerprint_os(ip, port):
    fingerprint_map = dict(zip(OS_FINGERPRINTS.values(), OS_FINGERPRINTS.keys()))
    
    sock = create_socket(ip, port)
    sock.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")

    res = binascii.hexlify(s.recv(2048)).decode()
    
    sock.close()

    if res in fingerprint_map.keys():
        return fingerprint_map[res]
    return ""

def log(msg):
    print("[+] {}".format(msg))

# -----------------------------------------------------------------------------
# RDP Class Implementation

class RDP():
    """
    This class implements the RDP protocol.
    """

    def __init__(self):
        self.sock    = None
        self.verbose = False

    # open connection and run the scan
    def run_scan(self, ip, port, verbose):
        self.sock    = create_socket(ip, port)
        self.verbose = verbose 
        
        res = self.rdp_scan_vuln()

        self.sock.close()

        self.sock    = None
        self.verbose = False

        return res

    # determine if target is vulnerable, assuming it has RDP enabled
    def rdp_scan_vuln(self):
        # determine if target has RDP enabled by sending connection request
        if not self.rdp_scan_enabled():
            return False

        # send MCS connect initial with GCC conference create
        res = self.rdp_send_recv(self.rdp_connect_initial())

        # parse the MCS connect initial with GCC conference create response
        rsmod, rsexp, rsran, server_rand, bitlen = self.rdp_parse_server_data(res)

        # erect domain and attach user 
        self.rdp_send(self.rdp_erect_domain_request())
        res = self.rdp_send_recv(self.rdp_attach_user_request())
        initiator = res[-2:]

        # send channel requests
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1009)))
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1003)))
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1004)))
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1005)))
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1006)))
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1007)))
        self.rdp_send_recv(self.rdp_channel_join_request(initiator, struct.pack('>H', 1008)))

        # begin security exchange
        client_rand = b'\x41' * 32
        rcran = int.from_bytes(client_rand, byteorder="little")
        security_exchange_pdu = self.rdp_security_exchange(rcran, rsexp, rsmod, bitlen)
        self.rdp_send(security_exchange_pdu)

        # compute the session RC4 keys
        rc4_enc_start, rc4_dec_start, hmackey, sessblob = self.rdp_calculate_rc4_keys(client_rand, server_rand)
        rc4_ctx = RC4(rc4_enc_start)

        # send (encrypted) client info PDU, rev license packet
        res = self.rdp_send_recv(self.rdp_encrypted_pkt(self.rdp_client_info(), rc4_ctx, hmac_key, b"\x48\x00"))

        # recv server demand active packet
        res = self.rdp_recv()

        # send (encrypted) client confirm active PDU
        self.rdp_send(self.rdp_encrypted_pkt(self.rdp_client_confirm_active(), rc4_ctx, hmac_key, b"\x38\x00"))
        
        # send (encrypted) synchonrize PDU
        self.rdp_send(self.rdp_encrypted_pkt(binascii.unhexlify("16001700f103ea030100000108001f0000000100ea03"), rc4_ctx, hmac_key))

        # send (encrypted) client control cooperate PDU
        self.rdp_send(self.rdp_encrypted_pkt(binascii.unhexlify("1a001700f103ea03010000010c00140000000400000000000000"), rc4_ctx, hmac_key))

        # send (encrypted) client control request control PDU
        self.rdp_send(self.rdp_encrypted_pkt(binascii.unhexlify("1a001700f103ea03010000010c00140000000100000000000000"), rc4_ctx, hmac_key))

        # send (encrypted) persistent key list PDU
        self.rdp_send(self._rdp_encrypted_pkt(self.rdp_client_persistent_key_list(), rc4_ctx, hmac_key))
        
        # send (encrypted) font list PDU
        self.rdp_send(self.rdp_encrypted_pkt(binascii.unhexlify("1a001700f103ea03010000010c00270000000000000003003200"), rc4_ctx, hmac_key))

        # session now fully established; attempt to unbind 
        return self.rdp_try_unbind(rc4_ctx, hmac_key)

    # determine if target has RDP enabled
    def rdp_scan_enabled(self):
        try:
            # send the initial connection request PDU
            self.rdp_send_recv(self.rdp_connection_request())
        except Exception as e:
            return False
        return True

    # attempt to unbind MS_T120 (where the magic happens)
    def rdp_try_unbind(self, rc4_enc_key, hmac_key):
        for i in range(5):
            res = self.rdp_recv()
        for j in range(5):
            self.rdp_send(
                self.rdp_encrypted_pkt(
                    binascii.unhexlify("100000000300000000000000020000000000000000000000"), 
                    rc4_enc_key, 
                    hmac_key, 
                    b"\x08\x00", 
                    b"\x00\x00", 
                    b"\x03\xed"
                )
            )
            self.rdp_send(
                self.rdp_encrypted_pkt(
                    binascii.unhexlify("20000000030000000000000000000000020000000000000000000000000000000000000000000000"), 
                    rc4_enc_key, 
                    hmac_key, 
                    b"\x08\x00", 
                    b"\x00\x00", 
                    b"\x03\xed"
                )
            )
            for i in range(3):
                res = self.rdp_recv()
                if binascii.unhexlify("0300000902f0802180") in res:
                    return True
        return False

# -----------------------------------------------------------------------------
# Socket Primitives

    def rdp_send_recv(self, data):
        self.rdp_send(data)
        return self.rdp_recv()

    def rdp_send(self, data):
        self.sock.sendall(data)

    def rdp_recv(self):
        tptk_header = self.sock.recv(4)
        body = self.sock.recv(int.from_bytes(tptk_header[2:4], byteorder="big"))
        return tptk_header + body

# -----------------------------------------------------------------------------
# Specialized Response Parsing

    # parse security exchange data from server response
    def rdp_parse_server_data(self, pkt):
        ptr = 0
        rdp_pkt = pkt[0x49:]
        while ptr < len(rdp_pkt):
            header_type = rdp_pkt[ptr:ptr+2]
            header_length = int.from_bytes(rdp_pkt[ptr+2:ptr+4], byteorder="little")
            #self._log("header type: %s, header length: %d" % (self._bin_to_hex(header_type), header_length))

            if header_type == b"\x02\x0c":
                server_random   = rdp_pkt[ptr+20:ptr+52]
                public_exponent = rdp_pkt[ptr+84:ptr+88]
                
                modulus = rdp_pkt[ptr+88:ptr+152]
                bitlen  = int.from_bytes(rdp_pkt[ptr+72:ptr+76], byteorder="little") - 8
                modulus = rdp_pkt[ptr+88:ptr+88+bitlen]

            ptr += header_length

        rsmod = int.from_bytes(modulus, byteorder="little")
        rsexp = int.from_bytes(public_exponent, byteorder="little")
        rsran = int.from_bytes(server_random, byteorder="little")

        return rsmod, rsexp, rsran, server_random, bitlen

# -----------------------------------------------------------------------------
# Protocol PDUs

    # X.224 Connection Request PDU
    def rdp_connection_request(self):
        return (
            b"\x03\x00"             # TPTK, Version: 3, Reserved: 0
            b"\x00\x2b"             # Length
            b"\x26"                 # X.224 Length
            b"\xe0"                 # X.224 PDU Type
            b"\x00\x00"             #  Destination reference
            b"\x00\x00"             # Source reference
            b"\x00"                 # Class
            b"\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x75\x73\x65\x72\x30\x0d\x0a" # Token
            b"\x01"                 # RDP Type
            b"\x00"                 # Flags
            b"\x08"                 # Length
            b"\x00\x00\x00\x00\x00" # requestedProtocols, TLS security supported: False, CredSSP supported: False
        )

    # MCS Connection Initial with GCC Conference Create Request
    def rdp_connect_initial(self):
        return (
            b"\x03\x00\x01\xca\x02\xf0\x80\x7f\x65\x82\x01\xbe\x04\x01"
            b"\x01\x04\x01\x01\x01\x01\xff\x30\x20\x02\x02\x00\x22\x02\x02\x00"
            b"\x02\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00"
            b"\x01\x02\x02\xff\xff\x02\x02\x00\x02\x30\x20\x02\x02\x00\x01\x02"
            b"\x02\x00\x01\x02\x02\x00\x01\x02\x02\x00\x01\x02\x02\x00\x00\x02"
            b"\x02\x00\x01\x02\x02\x04\x20\x02\x02\x00\x02\x30\x20\x02\x02\xff"
            b"\xff\x02\x02\xfc\x17\x02\x02\xff\xff\x02\x02\x00\x01\x02\x02\x00"
            b"\x00\x02\x02\x00\x01\x02\x02\xff\xff\x02\x02\x00\x02\x04\x82\x01"
            b"\x4b\x00\x05\x00\x14\x7c\x00\x01\x81\x42\x00\x08\x00\x10\x00\x01"
            b"\xc0\x00\x44\x75\x63\x61\x81\x34\x01\xc0\xd8\x00\x04\x00\x08\x00"
            b"\x20\x03\x58\x02\x01\xca\x03\xaa\x09\x04\x00\x00\x28\x0a\x00\x00"
            b"\x78\x00\x31\x00\x38\x00\x31\x00\x30\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00"
            b"\x00\x00\x00\x00\x18\x00\x07\x00\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x04\xc0\x0c\x00\x09\x00\x00\x00\x00\x00\x00\x00\x02\xc0\x0c\x00"
            b"\x03\x00\x00\x00\x00\x00\x00\x00\x03\xc0\x44\x00\x05\x00\x00\x00"
            b"\x63\x6c\x69\x70\x72\x64\x72\x00\xc0\xa0\x00\x00\x4d\x53\x5f\x54"
            b"\x31\x32\x30\x00\x80\x80\x00\x00\x72\x64\x70\x73\x6e\x64\x00\x00"
            b"\xc0\x00\x00\x00\x73\x6e\x64\x64\x62\x67\x00\x00\xc0\x00\x00\x00"
            b"\x72\x64\x70\x64\x72\x00\x00\x00\x80\x80\x00\x00"
        )

    # MCS Erect Domain Request PDU
    def rdp_erect_domain_request(self):
        return (
            b"\x03\x00\x00\x0c\x02\xf0\x80\x04\x00\x01\x00\x01"
        )

    # MCS Attach User Request PDU
    def rdp_attach_user_request(self):
        return (
            b"\x03"             # TPKT Version: 3
            b"\x00"             # Reserved: 0
            b"\x00\x08"         # Length: 8
            b"\x02\xf0\x80\x28"
        )

    # MCS Channel Join Request PDU(s)
    def rdp_channel_join_request(self, initiator, channelId):
        return (
            b"\x03\x00\x00\x0c\x02\xf0\x80\x38%s%s"
        ) % (initiator, channelId)

    # Security Exchange PDU
    def rdp_security_exchange(self, rcran, rsexp, rsmod, bitlen):
        x = (rcran ** rsexp) % rsmod
        nbytes, rem = divmod(x.bit_length(), 8)
        if rem:
            nbytes += 1
        encrypted_client_random = x.to_bytes(nbytes, byteorder="little")
        bitlen += 8
        userdata_length = 8 + bitlen
        userdata_length_low = userdata_length & 0xFF
        userdata_length_high = userdata_length // 256
        flags = 0x80 | userdata_length_high
        return (
            b"\x03\x00%s" % (userdata_length + 15).to_bytes(2, byteorder="big") + # TPTK
            b"\x02\xf0\x80"                                                       # X.224
            b"\x64"                                                               # sendDataRequest
            b"\x00\x08"                                                           # initiator
            b"\x03\xeb"                                                           # channelId
            b"\x70"                                                               # dataPriority
            b"%s" % (flags).to_bytes(1, byteorder="big") +
            b"%s" % (userdata_length_low).to_bytes(1, byteorder="big") +          # UserData length
            b"\x01\x00"                                                           # securityHeader flags
            b"\x00\x00"                                                           # securityHeader flagsHi
            b"%s" % (bitlen).to_bytes(4, byteorder="little") +                    # securityPkt length
            b"%s" % encrypted_client_random +                                     # 64 bytes encrypted client random 
            b"\x00\x00\x00\x00\x00\x00\x00\x00"                                   # 8 bytes rear padding
        )

    # Client Info PDU
    def rdp_client_info(self):
        pdu = "000000003301000000000a0000000000000000007500730065007200300000"
        pdu += "0000000000000002001c003100390032002e003100360038002e0031002e0"
        pdu += "032003000380000003c0043003a005c00570049004e004e0054005c005300"
        pdu += "79007300740065006d00330032005c006d007300740073006300610078002"
        pdu += "e0064006c006c000000a40100004700540042002c0020006e006f0072006d"
        pdu += "0061006c00740069006400000000000000000000000000000000000000000"
        pdu += "00000000000000000000000000000000000000a0000000500030000000000"
        pdu += "0000000000004700540042002c00200073006f006d006d006100720074006"
        pdu += "9006400000000000000000000000000000000000000000000000000000000"
        pdu += "00000000000000000000000300000005000200000000000000c4ffffff000"
        pdu += "00000270000000000"
        return binascii.unhexlify(pdu)

    # Client Confirm Active PDU
    def rdp_client_confirm_active(self):
        pdu  = "a4011300f103ea030100ea0306008e014d53545343000e000000010018000"
        pdu += "10003000002000000000d04000000000000000002001c0010000100010001"
        pdu += "0020035802000001000100000001000000030058000000000000000000000"
        pdu += "000000000000000000000010014000000010047012a000101010100000000"
        pdu += "010101010001010000000000010101000001010100000000a106000000000"
        pdu += "0000084030000000000e40400001300280000000003780000007800000050"
        pdu += "010000000000000000000000000000000000000000000008000a000100140"
        pdu += "014000a0008000600000007000c00000000000000000005000c0000000000"
        pdu += "0200020009000800000000000f000800010000000d0058000100000009040"
        pdu += "00004000000000000000c0000000000000000000000000000000000000000"
        pdu += "0000000000000000000000000000000000000000000000000000000000000"
        pdu += "0000000000000000000000000000000000c000800010000000e0008000100"
        pdu += "000010003400fe000400fe000400fe000800fe000800fe001000fe002000f"
        pdu += "e004000fe008000fe000001400000080001000102000000"
        return binascii.unhexlify(pdu)

    # Persistent Key List PDU
    def rdp_client_persistent_key_list(self):
        pdu  = "49031700f103ea03010000013b031c0000000100000000000000000000000"
        pdu += "0000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        pdu += "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        return binascii.unhexlify(pdu)

# -----------------------------------------------------------------------------
# RDP Internal Crypto
# (should probably just use an existing SSL/TLS module)

    def rdp_encrypted_pkt(self, data, rc4_enc_key, hmac_key, flags=b"\x08\x00", flags_hi=b"\x00\x00", channel_id=b"\x03\xeb"):
        user_data_len = len(data) + 12
        udl_with_flag = 0x8000 | user_data_len
        pkt = (
            b"\x02\xf0\x80"                                         # X.224
            b"\x64"                                                 # sendDataRequest
            b"\x00\x08"                                             # initiator
            b"%s" % channel_id +                                    # channelId
            b"\x70"                                                 # dataPriority
            b"%s" % (udl_with_flag.to_bytes(2, byteorder="big")) +  # udl_with_flag
            b"%s" % flags +                                         # flags  SEC_INFO_PKT | SEC_ENCRYPT
            b"%s" % flags_hi +                                      # flags_hi
            b"%s" % self.rdp_hmac(hmac_key, data)[0:8] +            # rdp_hmac
            b"%s" % self.rdp_rc4_crypt(rc4_enc_key, data)           # rdp_rc4_encrypt
        )
        tpkt = (
            b"\x03\x00"
            b"%s" % ((len(pkt) + 4).to_bytes(2, byteorder="big")) +
            b"%s" % pkt
        )
        return tpkt

    def rdp_hmac(self, hmac_key, data):
        s = hashlib.sha1()
        m = hashlib.md5()
        pad1 = b'\x36' * 40
        pad2 = b'\x5c' * 48
        s.update(hmac_key + pad1 + len(data).to_bytes(4, byteorder="little") + data)
        m.update(hmac_key + pad2 + s.digest())
        return m.digest()

    def rdp_rc4_crypt(self, cipher_ctx, data):
        return cipher_ctx.crypt(data)

    def rdp_calculate_rc4_keys(self, client_random, server_random):
        pre_master_secret = client_random[0:24] + server_random[0:24]

        master_secret  = self.rdp_salted_hash(pre_master_secret, b"A", client_random, server_random)  
        master_secret += self.rdp_salted_hash(pre_master_secret, b"BB", client_random, server_random) 
        master_secret += self.rdp_salted_hash(pre_master_secret, b"CCC", client_random, server_random)

        session_key_blob  = self.rdp_salted_hash(master_secret, b"X", client_random, server_random)
        session_key_blob += self.rdp_salted_hash(master_secret, b"YY", client_random, server_random)
        session_key_blob += self.rdp_salted_hash(master_secret, b"ZZZ", client_random, server_random)

        initial_client_decrypt_key128 = self.rdp_final_hash(session_key_blob[16:32], client_random, server_random)
        initial_client_encrypt_key128 = self.rdp_final_hash(session_key_blob[32:48], client_random, server_random)

        mac_key = session_key_blob[0:16]

        """
        self._log("PreMasterSecret: %s" % self._bin_to_hex(preMasterSecret))
        self._log("MasterSecret: %s" % self._bin_to_hex(masterSecret))
        self._log("sessionKeyBlob: %s" % self._bin_to_hex(sessionKeyBlob))
        self._log("mackey: %s" % self._bin_to_hex(macKey))
        self._log("initialClientDecryptKey128: %s" % self._bin_to_hex(initialClientDecryptKey128))
        self._log("initialClientEncryptKey128: %s" % self._bin_to_hex(initialClientEncryptKey128))
        """

        return initial_client_encrypt_key128, initial_client_decrypt_key128, mac_key, session_key_blob

    def rdp_salted_hash(self, s_bytes, i_bytes, client_random_bytes, server_random_bytes):
        m = hashlib.md5()
        s = hashlib.sha1()
        s.update(i_bytes + s_bytes + client_random_bytes + server_random_bytes)
        m.update(s_bytes + s.digest())
        return m.digest()

    def rdp_final_hash(self, k, client_random_bytes, server_random_bytes):
        m = hashlib.md5()
        m.update(k + client_random_bytes + server_random_bytes)
        return m.digest()

# -----------------------------------------------------------------------------
# Utility Functions

    # log if verbose output enabled
    def log_v(self, msg):
        if self.verbose:
            self.log(msg)

    # unconditionally log
    def log(self, msg):
        print("[+] {}".format(msg))

    def bin_to_hex(self, data):
        return "".join("%.2x" % i for i in data)

# -----------------------------------------------------------------------------
# RC4 Class Implementation

class RC4:
    """
    This class implements the RC4 stream cipher.
    Derived from http://cypherpunks.venona.com/archive/1994/09/msg00304.html
    """

    def __init__(self, key, streaming=True):
        assert(isinstance(key, (bytes, bytearray)))

        # initialize the internal state with key (key schedule)
        j = 0
        state = list(range(0x100))
        for i in range(0x100):
            j = (state[i] + key[i % len(key)] + j) & 0xFF
            state[i], state[j] = state[j], state[i]
        self.state = state

        # in streaming mode, we retain the keystream state between crypt() invocations
        if streaming:
            self.keystream = self.keystream_generator()
        else:
            self.keystream = None

    # encrypt / decrypt data - equivalent operations for stream cipher
    def crypt(self, data):
        assert(isinstance(data, (bytes, bytearray)))

        keystream = self.keystream or self.keystream_generator()
        return bytes([a ^ b for a, b in zip(data, keystream)])

    # generator that returns bytes of keystream on demand
    def keystream_generator(self):
        x = 0
        y = 0
        state = self.state.copy()
        while True:
            x = (x + 1) & 0xFF
            y = (state[x] + y) & 0xFF
            state[x], state[y] = state[y], state[x]
            i = (state[x] + state[y]) & 0xFF
            yield state[i]

def crypto_test():
    print("[+] Crypto quick selftest")

    key = bytes([i for i in range(16)])
    pt  = "A man, a plan, a canal: Panama".encode("utf-8")
    
    # for quicktest, streaming must be set to false
    # ensure we get the same keystream for both crypt operations
    cipher = RC4(key, streaming=False)

    print("[+] Plaintext:")
    print(pt.decode("utf-8"))
    print("")

    ct = cipher.crypt(pt)

    print("[+] Ciphertext:")
    hexdump(ct, 16)
    print("")

    nt = cipher.crypt(ct)

    print("[+] Newtext:")
    print(nt.decode("utf-8"))

def hexdump(data, width):
    for i in range(0, len(data), width):
        for j in range(i, i + width):
            if j > (len(data) - 1):
                break
            sys.stdout.write(hex(data[j]) + " ")
        sys.stdout.write("\n")
    sys.stdout.flush()

# -----------------------------------------------------------------------------
# Script Entry

if __name__ == "__main__":
    main()