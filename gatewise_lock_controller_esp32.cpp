#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <time.h>

const char* ssid = "<SSID>";
const char* password = "<PASSWORD>";

const char* mqtt_server = "broker.hivemq.com";
const int mqtt_port = 1883;

const char* BASE_URL = "https://gatewiseiot.com";
const int SPACE_ID = <<SPACE_ID>>;

String MQTT_TOPIC = "command/" + String(SPACE_ID) + "/open-lock";

WiFiClient espClient;
PubSubClient client(espClient);

const int LOCK_PIN = 21;
const int INTERNET_LED_PIN = 15;
const int GREEN_LED_PIN = 22;
const int BUTTON_PIN = 4;

unsigned long lastInternetCheck = 0;
const unsigned long checkInterval = 10000;
unsigned long lastBlink = 0;
const unsigned long blinkInterval = 1000;
bool ledState = false;

bool hasInternet = false;

bool isUnlocked = false;
unsigned long unlockStartTime = 0;
const unsigned long unlockDuration = 3000;

int lastButtonState = HIGH;
unsigned long lastDebounceTime = 0;
const unsigned long debounceDelay = 50;

const char* PRIVATE_KEY_PEM = "<<PRIVATE_KEY>>";

const char* PUBLIC_KEY_PEM = "<<PUBLIC_KEY>>";

mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

void setup() {
  delay(1000);
  Serial.begin(115200);

  pinMode(LOCK_PIN, OUTPUT);
  pinMode(INTERNET_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  digitalWrite(LOCK_PIN, LOW);
  digitalWrite(INTERNET_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);

  connectWiFi();
  checkInternet();

  configTime(0, 0, "pool.ntp.org", "time.google.com");

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char* pers = "rsa_sign";
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char*) pers, strlen(pers));
  if (ret != 0) {
    Serial.print("Failed to initialize RNG: ");
    Serial.println(ret);
  }

  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);

  reconnectMQTT();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED || WiFi.localIP().toString() == "0.0.0.0") {
    digitalWrite(INTERNET_LED_PIN, LOW);
    WiFi.disconnect();
    delay(100);
    connectWiFi();
    checkInternet();
  }

  if (!client.connected()) {
    reconnectMQTT();
  }

  client.loop();

  if (isUnlocked && millis() - unlockStartTime >= unlockDuration) {
    isUnlocked = false;
    digitalWrite(LOCK_PIN, LOW);
    digitalWrite(GREEN_LED_PIN, LOW);
  }

  int buttonReading = digitalRead(BUTTON_PIN);
  if (buttonReading != lastButtonState) {
    lastDebounceTime = millis();
  }
  if (millis() - lastDebounceTime > debounceDelay && buttonReading == LOW && !isUnlocked) {
    unlock();
  }
  lastButtonState = buttonReading;

  if (millis() - lastInternetCheck > checkInterval) {
    lastInternetCheck = millis();
    checkInternet();
  }

  updateInternetLed();
}

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.print("Connecting WiFi");
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.print(".");
    attempts++;
    if (attempts >= 20) {
      ESP.restart();
    }
  }
  Serial.println();
  Serial.println("WiFi connected");
  Serial.println(WiFi.localIP());
}

void checkInternet() {
  WiFiClient testClient;
  if (testClient.connect("clients3.google.com", 80)) {
    hasInternet = true;
    testClient.stop();
  } else {
    hasInternet = false;
  }
}

void updateInternetLed() {
  if (WiFi.status() != WL_CONNECTED) {
    digitalWrite(INTERNET_LED_PIN, LOW);
    return;
  }
  if (hasInternet) {
    digitalWrite(INTERNET_LED_PIN, HIGH);
    return;
  }
  if (millis() - lastBlink >= blinkInterval) {
    lastBlink = millis();
    ledState = !ledState;
    digitalWrite(INTERNET_LED_PIN, ledState ? HIGH : LOW);
  }
}

void reconnectMQTT() {
  while (!client.connected()) {
    String clientId = "ESP32Lock_" + String(SPACE_ID);
    Serial.print("Connecting MQTT... ");
    if (client.connect(clientId.c_str())) {
      Serial.println("connected");
      client.subscribe(MQTT_TOPIC.c_str());
    } else {
      Serial.print("failed, rc=");
      Serial.println(client.state());
      delay(2000);
    }
  }
}

void callback(char* topic, byte* payload, unsigned int length) {
  StaticJsonDocument<512> doc;
  DeserializationError error = deserializeJson(doc, payload, length);
  if (error) return;

  String command = doc["command"] | "";
  String commandId = doc["commandId"] | "";
  long timestamp = doc["timestamp"] | 0;
  String signature = doc["signature"] | "";

  String signedMessage = command + ":" + String(timestamp);

  if (!verifySignature(signedMessage, signature)) return;

  if (command == "open" && commandId != "") {
    sendConfirmation(commandId);
  }
}

bool verifySignature(const String& message, const String& signature_b64) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  int ret = mbedtls_pk_parse_public_key(&pk,
    (const unsigned char*)PUBLIC_KEY_PEM,
    strlen(PUBLIC_KEY_PEM) + 1);
  if (ret != 0) return false;

  unsigned char hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const unsigned char*)message.c_str(),
             message.length(), hash);

  unsigned char sig_bin[256];
  size_t sig_len = 0;
  ret = mbedtls_base64_decode(sig_bin, sizeof(sig_bin), &sig_len,
                              (const unsigned char*)signature_b64.c_str(),
                              signature_b64.length());
  if (ret != 0) return false;

  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig_bin, sig_len);
  mbedtls_pk_free(&pk);
  return (ret == 0);
}

String signMessage(const String& message) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  int ret = mbedtls_pk_parse_key(&pk,
    (const unsigned char*)PRIVATE_KEY_PEM,
    strlen(PRIVATE_KEY_PEM) + 1,
    NULL, 0, NULL, NULL);

  if (ret != 0) {
    Serial.print("Private key load error: ");
    Serial.println(ret);
    return "";
  }

  if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
    mbedtls_pk_free(&pk);
    return "";
  }

  unsigned char hash[32];
  ret = mbedtls_md(
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    (const unsigned char*)message.c_str(),
    message.length(),
    hash);
  if (ret != 0) {
    mbedtls_pk_free(&pk);
    return "";
  }

  unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
  size_t sig_len = 0;

  ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256,
                        hash, sizeof(hash),
                        sig, sizeof(sig), &sig_len,
                        mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_pk_free(&pk);

  if (ret != 0) {
    return "";
  }

  char base64_sig[512];
  size_t out_len = 0;
  ret = mbedtls_base64_encode((unsigned char*)base64_sig, sizeof(base64_sig), &out_len,
                              sig, sig_len);
  if (ret != 0) {
    return "";
  }

  base64_sig[out_len] = '\0';
  return String(base64_sig);
}

void sendConfirmation(const String& commandId) {
  long timestamp = time(nullptr);

  if (timestamp <= 100000) {
    Serial.println("NTP not synced yet.");
    return;
  }

  String message = "confirmed:" + commandId + ":" + String(timestamp);
  String signature = signMessage(message);
  if (signature == "") return;

  StaticJsonDocument<512> doc;
  doc["commandId"] = commandId;
  doc["timestamp"] = timestamp;
  doc["signature"] = signature;

  String body;
  serializeJson(doc, body);

  WiFiClientSecure secureClient;
  secureClient.setInsecure();

  HTTPClient http;
  http.begin(secureClient, String(BASE_URL) + "/api/spaces/access-confirmation");
  http.addHeader("Content-Type", "application/json");

  int code = http.POST(body);
  http.end();

  if (code == 200) {
    unlock();
  }
}

void unlock() {
  isUnlocked = true;
  unlockStartTime = millis();
  digitalWrite(LOCK_PIN, HIGH);
  digitalWrite(GREEN_LED_PIN, HIGH);
}