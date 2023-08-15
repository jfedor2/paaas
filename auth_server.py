#!/usr/bin/env python3

import hid
import struct
import binascii
import time
import socket

# Change if you're using a different controller than Razer Raion
VENDOR_ID = 0x1532
PRODUCT_ID = 0x1100


def add_crc(buf):
    return buf + struct.pack("<L", binascii.crc32(buf))


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", 6969))

d = hid.Device(VENDOR_ID, PRODUCT_ID)

print(d.manufacturer, d.product)
# print(bytes.hex(d.get_feature_report(0x03, 47 + 1), " "))

while True:
    try:
        received_data, client_address = s.recvfrom(4096)
        print("Received nonce from client.")
        # print(client_address, len(received_data), bytes.hex(received_data, " "))
        if len(received_data) != 257:
            raise Exception("unexpected packet length received")

        nonce_id = received_data[0]
        nonce = received_data[1:257]
        nonce += bytes([0] * 24)

        d.get_feature_report(0xF3, 7 + 1)  # RESET_AUTH

        print("Sending nonce to controller", end="", flush=True)
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
            print(".", end="", flush=True)
        print()

        print("Waiting for controller to sign", end="", flush=True)
        for _ in range(100):
            data = d.get_feature_report(0xF2, 15 + 1)  # GET_SIGNING_STATE
            # print(bytes.hex(data, " "))
            if data[2] == 0:
                print()
                break
            print(".", end="", flush=True)
            time.sleep(0.1)
        else:
            raise Exception("timeout waiting for signature")

        print("Getting signature from controller", end="", flush=True)
        signature = bytes()
        for n in range(19):
            data = d.get_feature_report(0xF1, 63 + 1)  # GET_SIGNATURE_NONCE
            print(".", end="", flush=True)
            if n != data[2]:
                raise Exception("wrong sequence while getting the signature")
            if nonce_id != data[1]:
                raise Exception("wrong nonce ID while getting the signature")
            signature += data[4:60]
            # print(bytes.hex(data[60:], " "))
        print()

        # print(bytes.hex(signature, " "))

        print("Sending signature to client...")
        s.sendto(signature, client_address)
    except Exception as e:
        print(e)
