#include <GEHQueue.h>

#define QUEUE_TIMEOUT 500

GEHQueue::GEHQueue(int maxNumberMessage) {
    this->msgQueue = xQueueCreate(maxNumberMessage, sizeof(GEHMessage));
}

bool GEHQueue::isEmpty() {
    return uxQueueMessagesWaiting(this->msgQueue) == 0;
}

bool GEHQueue::isFull() {
    return uxQueueSpacesAvailable(this->msgQueue) == 0;
}

bool GEHQueue::push(const GEHMessage& msg) {
    return xQueueSend(this->msgQueue, &msg, QUEUE_TIMEOUT) == pdTRUE;
}

GEHMessage GEHQueue::pop() {
    GEHMessage msg;
    xQueueReceive(this->msgQueue, &msg, QUEUE_TIMEOUT);
    return msg;
}
