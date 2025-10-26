#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "game.h"
#include "processor.h"


void init_buffering() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    setvbuf(stderr, NULL, 2, 0);
}


int main() {
    init_buffering();
    processor_init();
    game_loop();
    return 0;
}