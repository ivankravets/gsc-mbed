#ifndef GEHLISTENER_H_
#define GEHLISTENER_H_

#include <stdint.h>

class GEHListener {
public:
    virtual ~GEHListener() {};
    virtual void onMessage(const uint8_t *msg, const uint32_t length) = 0;
};

#endif // GEHLISTENER_H_
