#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <HTTPClient.h>

const char* ssid = "<SSID>";
const char* password = "<PASSWORD>";

const char* mqtt_server = "<MQQT_BROKER>";
WiFiClient espClient;
PubSubClient client(espClient);

const int LOCK_PIN = 21;
const int INTERNET_LED_PIN = 15;

unsigned long lastInternetCheck = 0;
const unsigned long checkInterval = 10000;
unsigned long lastBlink = 0;
const unsigned long blinkInterval = 1000;
bool ledState = false;

bool hasInternet = false;

const char* PRIVATE_KEY_PEM = R"(-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----)";

const char* PUBLIC_KEY_PEM = R"(-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----)";

mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

void setup() {
  delay(1000);
  Serial.begin(115200);

  pinMode(LOCK_PIN, OUTPUT);
  pinMode(INTERNET_LED_PIN, OUTPUT);
  digitalWrite(LOCK_PIN, LOW);
  digitalWrite(INTERNET_LED_PIN, LOW);

  connectWiFi();
  checkInternet();

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char* pers = "rsa_sign";
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char*) pers, strlen(pers));
  if (ret != 0) {
    Serial.print("Failed to initialize RNG: ");
    Serial.println(ret);
  }

  client.setServer(mqtt_server, 1883);
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

  if (client.connect("ESP32Lock")) {
  } else {
    reconnectMQTT();
  }

  client.loop();

  if (millis() - lastInternetCheck > checkInterval) {
    lastInternetCheck = millis();
    checkInternet();
  }

  if (WiFi.status() != WL_CONNECTED) {
    digitalWrite(INTERNET_LED_PIN, LOW);
  } else if (hasInternet) {
    digitalWrite(INTERNET_LED_PIN, HIGH);
  } else {
    if (millis() - lastBlink >= blinkInterval) {
      lastBlink = millis();
      ledState = !ledState;
      digitalWrite(INTERNET_LED_PIN, ledState ? HIGH : LOW);
    }
  }
}

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    attempts++;
    if (attempts >= 20) {
      ESP.restart();
    }
  }
}

void checkInternet() {
  WiFiClient client;
  if (client.connect("clients3.google.com", 80)) {
    hasInternet = true;
    client.stop();
  } else {
    hasInternet = false;
  }
}

void reconnectMQTT() {
  while (!client.connected()) {
    if (client.connect("ESP32Lock")) {
      client.subscribe("command/open-lock");
    } else {
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

  if (!verifySignature(signedMessage, signature)) {
    return;
  }

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
  String message = "confirmed:" + commandId + ":" + String(timestamp);
  String signature = signMessage(message);
  if (signature == "") return;

  HTTPClient http;
  http.begin("<BASE_URL>/api/labs/access-confirmation");
  http.addHeader("Content-Type", "application/json");

  StaticJsonDocument<512> doc;
  doc["commandId"] = commandId;
  doc["timestamp"] = timestamp;
  doc["signature"] = signature;

  String payload;
  serializeJson(doc, payload);

  int code = http.POST(payload);
  String response = http.getString();
  http.end();

  if (code == 200) {
    unlock();
  }
}

void unlock() {
  digitalWrite(LOCK_PIN, HIGH);
  delay(3000);
  digitalWrite(LOCK_PIN, LOW);
}