#ifndef GEHREGISTRATION_H
#define GEHREGISTRATION_H

#define INVALID_MESSAGE_ID 0
#define MAX_NUMBER_MESSAGE 1024

#include <FreeRTOS.h>

class GEHRegistration {
private:
    SemaphoreHandle_t mutex;
    bool tableMessageID[MAX_NUMBER_MESSAGE];

    GEHRegistration();
public:
    static GEHRegistration *Instance;

    uint16_t registerNextMessage();
    void unregisterMessage(uint16_t msgID);
    bool isMessageRegistered(uint16_t msgID);
};

#endif
