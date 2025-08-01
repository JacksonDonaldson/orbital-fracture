#include "payload_12_81.h"

/*
Stage 4: Implant
This is a sample implant, doesn't do anything particularly interesting
I doubt I need to explain the possibilities
*/
void __start(){

    
    debug_printf("running implant");

    while(1){
        // SOS
        debug_printf(".");
        for(int i = 0; i < 3; i++){
            send_to_tb(0xc4, 4);
            sleep(500);
            send_to_tb(0xc4, 0);
            sleep(250);
        }
        sleep(1000);
        for(int i = 0; i < 3; i++){
            send_to_tb(0xc4, 4);
            sleep(1000);
            send_to_tb(0xc4, 0);
            sleep(250);
        }
        sleep(1000);
    }
}