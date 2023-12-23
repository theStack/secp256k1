#!/usr/bin/env python3
import bech32m
import hashlib
import json
import ripemd160
import secp256k1_glue

def sha256(s):
    return hashlib.sha256(s).digest()

def hash160(s):
    return ripemd160.ripemd160(sha256(s))

def TaggedHash(tag, data):
    return sha256(sha256(tag) + sha256(tag) + data)

def smallest_outpoint(outpoints):
    serialized_outpoints = [bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little') for txid, n in outpoints]
    return sorted(serialized_outpoints)[0]

def encode_silent_payment_address(scan_pubkey, spend_pubkey):
    assert len(scan_pubkey) == 33
    assert len(spend_pubkey) == 33
    data = bech32m.convertbits(scan_pubkey + spend_pubkey, 8, 5)
    return bech32m.bech32_encode("sp", [0] + data, bech32m.Encoding.BECH32M)

def decode_silent_payments_address(address):
    version, data = bech32m.decode("sp", address)
    data = bytes(data)  # convert from list to bytes
    assert len(data) == 66
    return data[:33], data[33:]

def is_p2tr(s):  # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (len(s) == 34) and (s[0] == 0x51) and (s[1] == 0x20)

def is_p2wpkh(s):  # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return (len(s) == 22) and (s[0] == 0x00) and (s[1] == 0x14)

def is_p2sh(s):  # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return (len(s) == 23) and (s[0] == 0xA9) and (s[1] == 0x14) and (s[-1] == 0x87)

def is_p2pkh(s):  # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (len(s) == 25) and (s[0] == 0x76) and (s[1] == 0xA9) and (s[2] == 0x14) and (s[-2] == 0x88) and (s[-1] == 0xAC)

def get_pubkey_from_input(spk, script_sig, witness):
    if is_p2pkh(spk):
        spk_pkh = spk[3:3 + 20]
        for i in range(len(script_sig), 0, -1):
            if i - 33 >= 0:
                pk = script_sig[i - 33:i]
                if hash160(pk) == spk_pkh:
                    return pk
        # should never happen, as this would be an invalid spend
        assert False
    if is_p2sh(spk):
        redeem_script = script_sig[1:]
        if is_p2wpkh(redeem_script):
            return redeem_script[-33:]
    if is_p2wpkh(spk):
        # the witness must contain two items and the second item is the pubkey
        return witness[-33:]
    if is_p2tr(spk):
        return spk[2:]
    assert False

with open('./bip352-send_and_receive_test_vectors.json') as f:
    test_vectors = json.load(f)

passed_send, passed_receive = 0, 0
for test_nr, test_vector in enumerate(test_vectors):
    print(f"----- Test vector: \'{test_vector['comment']}\' {test_nr+1}/{len(test_vectors)} -----")
    ###################### sending #########################
    assert len(test_vector['sending']) == 1
    send_data_given = test_vector['sending'][0]['given']
    send_data_expected = test_vector['sending'][0]['expected']
    input_priv_keys = []
    outpoints = []
    for i in send_data_given['vin']:
        priv_key = i['private_key']
        pub_key = get_pubkey_from_input(bytes.fromhex(i['prevout']['scriptPubKey']['hex']),
            bytes.fromhex(i['scriptSig']), bytes.fromhex(i['txinwitness']))
        input_priv_keys.append((i['private_key'], len(pub_key) == 32))
        outpoints.append((i['txid'], i['vout']))
    outpoint_L = smallest_outpoint(outpoints)
    outputs_calculated = []

    groups = {}
    for recipient_address, recipient_value in send_data_given['recipients']:
        recipient_B_scan, recipient_B_spend = decode_silent_payments_address(recipient_address)
        groups.setdefault(recipient_B_scan, []).append((recipient_B_spend, recipient_value))

    for recipient_B_scan, recipient_spend_data in groups.items():
        plain_seckeys, xonly_seckeys = [], []
        for seckey_hex, is_taproot in input_priv_keys:
            (xonly_seckeys if is_taproot else plain_seckeys).append(bytes.fromhex(seckey_hex))
        tweak_data = secp256k1_glue.silentpayments_create_private_tweak_data(
            plain_seckeys, xonly_seckeys, outpoint_L)
        shared_secret = secp256k1_glue.silentpayments_send_create_shared_secret(tweak_data, recipient_B_scan)
        k = 0
        for recipient_B_spend in recipient_spend_data:
            output = secp256k1_glue.silentpayments_create_output_pubkey(shared_secret, recipient_B_spend[0], k)
            outputs_calculated.append(output.hex())
            k += 1
    outputs_expected = [o[0] for o in send_data_expected['outputs']]
    if outputs_calculated == outputs_expected:
        print("Sending test \033[0;32mPASSED. ✓\033[0m")
        passed_send += 1
    else:
        print("Sending test \033[0;31mFAILED. ✖\033[0m")
        print(f"Calculated outputs: {outputs_calculated}")
        print(f"Expected outputs: {outputs_expected}")

    ###################### receiving ########################
    assert len(test_vector['receiving']) >= 1
    for subtest_nr, receive_data in enumerate(test_vector['receiving']):
        receive_data_given = receive_data['given']
        receive_data_expected = receive_data['expected']

        input_pub_keys = []
        outpoints = []
        for i in receive_data_given['vin']:
            pub_key = get_pubkey_from_input(bytes.fromhex(i['prevout']['scriptPubKey']['hex']),
                bytes.fromhex(i['scriptSig']), bytes.fromhex(i['txinwitness']))
            input_pub_keys.append(pub_key)
            outpoints.append((i['txid'], i['vout']))
        receive_outpoint_L = smallest_outpoint(outpoints)

        # test data sanity check: outpoint_L of send and receive has to match
        assert receive_outpoint_L == outpoint_L
        # derive tweak_data and shared_secret
        plain_pubkeys, xonly_pubkeys = [], []
        for pubkey in input_pub_keys:
            if len(pubkey) == 32:
                xonly_pubkeys.append(pubkey)
            elif len(pubkey) == 33:
                plain_pubkeys.append(pubkey)
            else:
                assert False
        tweak_data = secp256k1_glue.silentpayments_create_tweak_data(plain_pubkeys, xonly_pubkeys, receive_outpoint_L)
        scan_privkey = bytes.fromhex(receive_data_given['key_material']['scan_priv_key'])
        spend_privkey = bytes.fromhex(receive_data_given['key_material']['spend_priv_key'])
        # spend pubkey is not in the given data of the receiver part, so let's compute it
        scan_pubkey = secp256k1_glue.pubkey_serialize((secp256k1_glue.pubkey_create(scan_privkey)))
        spend_pubkey = secp256k1_glue.pubkey_serialize((secp256k1_glue.pubkey_create(spend_privkey)))
        shared_secret = secp256k1_glue.silentpayments_receive_create_shared_secret(tweak_data, scan_privkey)
        outputs_pubkeys_expected = [o['pub_key'] for o in receive_data_expected['outputs']]
        outputs_privkeys_expected = [o['priv_key_tweak'] for o in receive_data_expected['outputs']]
        outputs_scanned = []
        outputs_privkeys = []

        # scan through outputs
        k = 0
        outputs_to_check = receive_data_given['outputs'].copy()
        while True:
            if len(outputs_to_check) == 0:
                break
            for output_to_check in outputs_to_check:
                found_sth = False
                for label_m in [None] + receive_data_given['labels']:
                    if label_m is None:
                        label_tweak = None
                    else:
                        label_tweak = secp256k1_glue.silentpayments_create_label_tweak(scan_privkey, label_m)
                    output_pubkey = secp256k1_glue.silentpayments_create_output_pubkey(shared_secret, spend_pubkey, k, label_tweak)
                    if output_pubkey.hex() in outputs_to_check:
                        outputs_to_check.remove(output_pubkey.hex())
                        outputs_scanned.append(output_pubkey.hex())
                        output_privkey = secp256k1_glue.silentpayments_create_output_seckey(shared_secret, spend_privkey, k, label_tweak)
                        # a bit hacky: subtract the receiver spend key from the output privkey to get the expected tweak
                        privkey_tweak = secp256k1_glue.seckey_subtract(output_privkey, spend_privkey)
                        outputs_privkeys.append(privkey_tweak.hex())
                        k += 1
                        found_sth = True
                        break
            if not found_sth:
                break

        all_subtests_passed = True
        # check if addresses match
        calculated_addresses = []
        for label_m in [None] + receive_data_given['labels']:
            if label_m is None:
                output_spend_pubkey = spend_pubkey
            else:
                label_tweak = secp256k1_glue.silentpayments_create_label_tweak(scan_privkey, label_m)
                output_spend_pubkey = secp256k1_glue.silentpayments_create_address_spend_pubkey(spend_pubkey, label_tweak)
            output_address = encode_silent_payment_address(scan_pubkey, output_spend_pubkey)
            calculated_addresses.append(output_address)

        if calculated_addresses == receive_data_expected['addresses']:
            print(f"Receiving sub-test [addresses] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;32mPASSED. ✓\033[0m")
        else:
            print(f"Receiving sub-test [addresses] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;31mFAILED. ✖\033[0m")
            print(f"Calculated addresses: {calculated_addresses}")
            print(f"Expected addresses: {receive_data_expected['addresses']}")
            all_subtests_passed = False

        # check if output pubkey match
        if outputs_scanned == outputs_pubkeys_expected:
            print(f"Receiving sub-test [output pubkey] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;32mPASSED. ✓\033[0m")
        else:
            print(f"Receiving sub-test [output pubkey] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;31mFAILED. ✖\033[0m")
            print(f"Scanned output pubkeys: {outputs_scanned}")
            print(f"Expected outputs pubkeys: {outputs_expected}")
            all_subtests_passed = False

        # check if output spending keys also match
        if outputs_privkeys == outputs_privkeys_expected:
            print(f"Receiving sub-test [output privkey] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;32mPASSED. ✓\033[0m")
        else:
            print(f"Receiving sub-test [output privkey] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;31mFAILED. ✖\033[0m")
            print(f"Calculated output privkeys: {outputs_privkeys}")
            print(f"Expected outputs privkeys: {outputs_privkeys_expected}")
            all_subtests_passed = False

    if all_subtests_passed:
        print("Receiving test \033[0;32mPASSED. ✓\033[0m")
        passed_receive += 1
    else:
        print("Receiving test \033[0;31mFAILED. ✖\033[0m")

print( "+=================================+")
print( "| Summary:                        |")
print( "+---------------------------------+")
print(f"| {passed_send}/{len(test_vectors)} sending tests passed.     |")
print(f"| {passed_receive}/{len(test_vectors)} receiving tests passed.   |")
print( "+=================================+")
