#ifndef GEHQUEUE_H_
#define GEHQUEUE_H_

#include <GEHMessage.h>
#include <FreeRTOS.h>

class GEHQueue {
private:
    QueueHandle_t msgQueue;
public:
    GEHQueue(int maxNumberMessage);
    bool isEmpty();
    bool isFull();
    bool push(const GEHMessage& msg);
    GEHMessage pop();
};

#endif // GEHQUEUE_H_
