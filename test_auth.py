#!/usr/bin/env python3

import hid
import struct
import binascii
import time


def add_crc(buf):
    return buf + struct.pack("<L", binascii.crc32(buf))


d = hid.Device(0xCAFE, 0xBABA)

print(d.manufacturer, d.product)
print(bytes.hex(d.get_feature_report(0x03, 47 + 1), " "))

nonce_id = 66
nonce = bytes([0] * 256)
nonce += bytes([0] * 24)

print(bytes.hex(d.get_feature_report(0xF3, 7 + 1), " "))  # RESET_AUTH

for nonce_page in range(5):
    data = struct.pack(
        "<B BBB 56B",
        0xF0,
        nonce_id,
        nonce_page,
        0,
        *nonce[nonce_page * 56 : nonce_page * 56 + 56]
    )  # SET_AUTH_PAYLOAD
    d.send_feature_report(add_crc(data))

for _ in range(100):
    data = d.get_feature_report(0xF2, 15 + 1)  # GET_SIGNING_STATE
    print(bytes.hex(data, " "))
    if data[2] == 0:
        break
    time.sleep(0.1)
else:
    raise Exception("timeout waiting for signature")

signature = bytes()
for n in range(19):
    data = d.get_feature_report(0xF1, 63 + 1)  # GET_SIGNATURE_NONCE
    if n != data[2]:
        raise Exception("wrong sequence while getting the signature")
    if nonce_id != data[1]:
        raise Exception("wrong nonce ID while getting the signature")
    signature += data[4:60]

print(bytes.hex(signature, " "))
