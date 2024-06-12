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
  client->writeMessage(ALIASNAME, (uint8_t *)buffer, strlen(buffer), true);

  lastTime = millis();
}
