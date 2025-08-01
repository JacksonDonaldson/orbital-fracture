jacksondonaldson.com/blink
This folder contains a proof-of-concept against the Blink video doorbell. When run, it replaces the doorbell's firmware with instructions to spell out SOS repeatedly.

An attacker within range of the Blink's wifi network during initialization can exploit weak cryptography and a buffer overflow in key negotiation to gain arbitrary code execution.
They can then evade trusted boot and gain persistence by imitating the factory bundle and forcing the blink bootloader into recovery mode.

Exploitation:
    1. Acquire a blink running FW version 12.81. Reset it, if it's not already reset. 
        You'll want a backup of its flash memory if you want it to do anything after the attack.

    2. On a laptop near the doorbell:
        python3 poc_12_81.py [wifi interface] payload implanted_bundle

        The above will ask for sudo to run a few networking commands required for the attack.
        Requires airmon-ng and tshark
    
    3. Attempt to set up the doorbell through the blink app.
        After the phone connects to the blink's network, the attack will begin. 
    
    4. The blink will begin running attacker-controlled firmware.
        Currently, I have repeatedly spell out SOS on the red LED.
    
        This replaces the firmware of the blink, effectively bricking it until you reflash it.

        (firmware not included in public upload due to copyright)
    
At a high level, the attack consists of the following steps:

Step 1: Eavesdrop on initialization to gain cryptographic data necessary for the attack
Step 2: Exploit an overflow in the set key api to gain execution
Step 3: Use that execution to gain persistence
Step 4: Run whatever code you want whenever the doorbell boots

Steps 1 and 2 are implemented in poc_12_81.py
Step 3 is implemented in payload.c
Step 4 is implemented in implant.c

A detailed description of each step is included in the relevant file.
Logs from poc_12_81.py and from the serial output of the doorbell are included in poc_output.txt and blink_output.txt respectively.

Note:
    The key negotiation procedure appears to be device-agnostic.
    It seems likely that the same exploit would work against sync modules, mini-cameras, etc. 
    I haven't confirmed this though.
