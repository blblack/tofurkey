#!/usr/bin/env python3

import re
import struct
import nacl.hashlib
import pathlib


# Python's nacl bindings don't offer "crypto_kdf_blake2b_derive_from_key()",
# so we're reimplementing that here, but hardcoded for our exact use-case:
def kdf_blake2b_derive16_from_key(subkey_id, main_key):
    sksalt = struct.pack("<QQ", subkey_id, 0)
    persctx = b"tofurkey\0\0\0\0\0\0\0\0"
    return nacl.hashlib.blake2b(
        digest_size=16, key=main_key, salt=sksalt, person=persctx
    ).digest()


def validate_keys(interval, main_key, key_time, key_primary, key_backup):
    ctr_primary, leftover = divmod(key_time, interval)
    if leftover >= (interval >> 1):
        ctr_backup = ctr_primary + 1
    else:
        ctr_backup = ctr_primary - 1

    cmp_primary = kdf_blake2b_derive16_from_key(ctr_primary, main_key)
    if key_primary != cmp_primary:
        raise Exception(
            f"Test Failed primary key comparison - time: {key_time!s}"
            f" expected: {cmp_primary!a} got: {key_primary!a}"
        )
    cmp_backup = kdf_blake2b_derive16_from_key(ctr_backup, main_key)
    if key_backup != cmp_backup:
        raise Exception(
            f"Test Failed backup key comparison - time: {key_time!s}"
            f" expected: {cmp_backup!a} got: {key_backup!a}"
        )


def parse_key(key_ascii):
    return bytearray.fromhex(key_ascii.replace("-", ""))


def main():
    # These could be parameterized, but for now they're just fixed to match
    # the slow test's own hardcoded values
    interval = 10
    key_path = "t/test.key"
    log_path = "t/testout/log"
    main_key = pathlib.Path(key_path).read_bytes()
    tfo_re = re.compile(
        r"procfs write: \[([0-9]+)\] "
        r"([0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}),"
        r"([0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8})$"
    )
    count = 0
    key_times = []
    with open(log_path, "r") as log_file:
        for line in log_file.readlines():
            result = tfo_re.search(line)
            if result:
                count += 1
                key_time = int(result[1])
                key_times.append(key_time)
                validate_keys(
                    interval,
                    main_key,
                    key_time,
                    parse_key(result[2]),
                    parse_key(result[3]),
                )

    # During our 23 second test, there should be either 5 or 6 total outputs
    # (including the initial one before the timing loop starts!), depending on
    # natural timing.  The first periodic one should be %5==2, and the
    # remaining ones should be 5 seconds apart:
    if count < 5:
        raise Exception(
            f"Expected at least 5 total key output lines, got only {count!s}"
        )
    if key_times[1] % 5 != 2:
        raise Exception(f"First periodic key time {key_times[1]!s} % 5 != 2")
    for k in range(1, count - 1):
        if key_times[k + 1] - key_times[k] != 5:
            raise Exception(f"Key times not exactly 5 seconds apart")
    print(f"OK: {count!s} key outputs are correct")


if __name__ == "__main__":
    main()
