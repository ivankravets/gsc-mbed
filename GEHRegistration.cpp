#include <GEHRegistration.h>

GEHRegistration *GEHRegistration::Instance = new GEHRegistration();

GEHRegistration::GEHRegistration() {
    this->mutex = xSemaphoreCreateMutex();
    xSemaphoreGive(this->mutex);
    for (uint16_t idx = 0; idx < MAX_NUMBER_MESSAGE; ++idx) {
        tableMessageID[idx] = false;
    }
}

uint16_t GEHRegistration::registerNextMessage() {
    if (xSemaphoreTake(this->mutex, (TickType_t) 100) != pdTRUE) { // Waiting 1500ms
        return 0;
    }

    uint16_t msgID;
    for (uint16_t idx = 0; idx < MAX_NUMBER_MESSAGE; ++idx) {
        if (tableMessageID[idx] == false) {
            msgID = idx;
            break;
        }
    }

    if (msgID < MAX_NUMBER_MESSAGE) {
        tableMessageID[msgID] = true;
    }
    xSemaphoreGive(this->mutex);
    return msgID == MAX_NUMBER_MESSAGE ? 0 : msgID + 1;
}

void GEHRegistration::unregisterMessage(uint16_t msgID) {
    if (msgID == 0 || msgID > MAX_NUMBER_MESSAGE || xSemaphoreTake(this->mutex, (TickType_t) 100) != pdTRUE) { // Waiting 1500ms
        return;
    }
    tableMessageID[msgID - 1] = false;
    xSemaphoreGive(this->mutex);
}

bool GEHRegistration::isMessageRegistered(uint16_t msgID) {
    bool isRegistered = false;
    if (msgID == 0 || msgID > MAX_NUMBER_MESSAGE || xSemaphoreTake(this->mutex, (TickType_t) 100) != pdTRUE) { // Waiting 1500ms
        return isRegistered;
    }
    isRegistered = tableMessageID[msgID - 1];
    xSemaphoreGive(this->mutex);
    return isRegistered;
}
