#!/usr/bin/env python3
import bech32m
import hashlib
import json
import secp256k1_glue

def sha256(s):
    return hashlib.sha256(s).digest()

def calculate_outpoints_hash(outpoints):
    serialized_outpoints = [bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little') for txid, n in outpoints]
    return sha256(b"".join(sorted(serialized_outpoints)))

def decode_silent_payments_address(address):
    version, data = bech32m.decode("sp", address)
    data = bytes(data)  # convert from list to bytes
    assert len(data) == 66
    return data[:33], data[33:]

with open('./bip352-send_and_receive_test_vectors.json') as f:
    test_vectors = json.load(f)

passed_send, passed_receive = 0, 0
for test_nr, test_vector in enumerate(test_vectors):
    print(f"----- Test vector: \'{test_vector['comment']}\' {test_nr+1}/{len(test_vectors)} -----")
    ###################### sending #########################
    assert len(test_vector['sending']) == 1
    send_data_given = test_vector['sending'][0]['given']
    send_data_expected = test_vector['sending'][0]['expected']
    input_priv_keys = send_data_given['input_priv_keys']
    outpoints_hash = calculate_outpoints_hash(send_data_given['outpoints'])
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
            plain_seckeys, xonly_seckeys, outpoints_hash)
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
    if test_vector['receiving'][0]['supports_labels']:
        print("Receiving test SKIPPED. (labels are not implemented yet)")
        continue
    for subtest_nr, receive_data in enumerate(test_vector['receiving']):
        receive_data_given = receive_data['given']
        receive_data_expected = receive_data['expected']
        # test data sanity check: outpoints hashes of send and receive has to match
        receive_outpoints_hash = calculate_outpoints_hash(receive_data_given['outpoints'])
        assert outpoints_hash == receive_outpoints_hash
        # derive tweak_data and shared_secret
        plain_pubkeys, xonly_pubkeys = [], []
        for pubkey in receive_data_given['input_pub_keys']:
            pubkey = bytes.fromhex(pubkey)
            if len(pubkey) == 32:
                xonly_pubkeys.append(pubkey)
            elif len(pubkey) == 33:
                plain_pubkeys.append(pubkey)
            else:
                assert False
        tweak_data = secp256k1_glue.silentpayments_create_tweak_data(plain_pubkeys, xonly_pubkeys, outpoints_hash)
        scan_privkey = bytes.fromhex(receive_data_given['scan_priv_key'])
        spend_privkey = bytes.fromhex(receive_data_given['spend_priv_key'])
        # spend pubkey is not in the given data of the receiver part, so let's compute it
        scan_pubkey = secp256k1_glue.pubkey_serialize((secp256k1_glue.pubkey_create(scan_privkey)))
        spend_pubkey = secp256k1_glue.pubkey_serialize((secp256k1_glue.pubkey_create(spend_privkey)))
        shared_secret = secp256k1_glue.silentpayments_receive_create_shared_secret(tweak_data, scan_privkey)
        outputs_pubkeys_expected = [o['pub_key'] for o in receive_data_expected['outputs']]
        outputs_privkeys_expected = [o['priv_key_tweak'] for o in receive_data_expected['outputs']]
        outputs_scanned = []
        outputs_k_values = []

        # scan through outputs
        k = 0
        while True:
            output_pubkey = secp256k1_glue.silentpayments_create_output_pubkey(shared_secret, spend_pubkey, k)
            continue_scan = False
            for output_given in receive_data_given['outputs']:
                if bytes.fromhex(output_given) == output_pubkey:
                    outputs_scanned.append(output_given)
                    outputs_k_values.append(k)
                    continue_scan = True
            if not continue_scan:
                break
            k += 1

        all_subtests_passed = True
        if outputs_scanned == outputs_pubkeys_expected:
            print(f"Receiving sub-test [output pubkey] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;32mPASSED. ✓\033[0m")
        else:
            print(f"Receiving sub-test [output pubkey] {subtest_nr+1}/{len(test_vector['receiving'])} \033[0;31mFAILED. ✖\033[0m")
            print(f"Scanned output pubkeys: {outputs_scanned}")
            print(f"Expected outputs pubkeys: {outputs_expected}")
            all_subtests_passed = False

        # check if output spending key also matches
        outputs_privkeys = []
        for k in outputs_k_values:
            output_privkey = secp256k1_glue.silentpayments_create_output_seckey(shared_secret, spend_privkey, k)
            # a bit hacky: subtract the receiver spend key from the output privkey to get the expected tweak
            privkey_tweak = secp256k1_glue.seckey_subtract(output_privkey, spend_privkey)
            outputs_privkeys.append(privkey_tweak.hex())

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
