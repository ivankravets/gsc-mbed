Library is used in Embedded System to connect to Goldeneye Hubs System.

## Requirement
1. This library is used for microcontroller ESP with Arduino framework.

2. You should use [VSCode](https://code.visualstudio.com/) + [PlatformIO](https://platformio.org/) for development.

## Install
1. Download `gsc-services.json` from here (comming soon).

2. Copy `gsc-services.json` to folder `data` in your project PlatformIO (create folder `data` if it is not existed).

3. Run command: `pio install GSCMbedLib`.

4. This library uses [`nanopb`](https://github.com/nanopb/nanopb) to parse messages, you need to [download](https://github.com/gecosys/gsc-mbed-grpc) and keep some files in folder `lib/grpc` of your project PlatformIO (create folder `grpc` if it is not existed)

## Example

```c++
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <GEHClient.h>

// Other connections will send messages to yours by this ALIASNAME
#define ALIASNAME {ALIASNAME}

// Information of your WiFi
#define WIFI_SSID {WIFI_SSID}
#define WIFI_PSWD {WIFI_PSWD}

// GEListener will listen comming messages
class GEListener: public GEHListener {
  void onMessage(const uint8_t *msg, const size_t length) {
    for(size_t idx = 0; idx < length; ++idx) {
      Serial.print((char)msg[idx]);
    }
    Serial.println();
  }
};

int32_t lastTime = 0;
GEListener *listener = new GEListener();
GEHClient *client = GEHClient::Instance();

void setup() {
  Serial.begin(115200);

  // Setup WiFi
  WiFi.enableAP(false);
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PSWD);
  WiFi.mode(WIFI_STA);
  esp_wifi_set_ps(WIFI_PS_NONE); // Turn off Power Safe mode

  // Waiting for connecting to the WiFi
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
  }
  Serial.println();
  Serial.println("Connected WiFi");

  // Register object which will receive comming messages
  client->setListener(listener);
  
  // Open connection to Goldeneye Hubs System with the ALIASNAME
  client->open(ALIASNAME);
}

void loop() {
  // Read next message
  client->nextMessage();

  // Send message every 3 seconds
  if (lastTime + 3000 > millis()) {
    return;
  }

  // Send message to yourself
  char buffer[] = "Goldeneye Technologies";
  client->writeMessage(ALIASNAME, (uint8_t *)buffer, strlen(buffer));

  lastTime = millis();
}
```
