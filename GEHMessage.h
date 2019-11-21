#ifndef GEHMESSAGE_H
#define GEHMESSAGE_H

#include <stdint.h>

#define GEHMessage_init_default GEHMessage{0, nullptr}

struct GEHMessage {
    uint32_t length;
    uint8_t *content;
};

#endif
