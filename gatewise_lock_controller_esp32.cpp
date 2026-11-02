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
#include <IRremoteESP8266.h>
#include <IRsend.h>
#include <IRrecv.h>
#include <IRac.h>
#include <IRutils.h>

void connectWiFi();
void checkInternet();
void updateInternetLed();
void reconnectMQTT();
void callback(char* topic, byte* message, unsigned int length);
bool wasRecentlyExecuted(const String& commandId);
void rememberCommand(const String& commandId);
String sendAirConditionerCommand(JsonObject airConditioner);
String sendIrCommand(JsonObject ir);
void startLearnMode(const String& commandId, int timeoutSec);
void stopLearnMode();
void pauseLearnMode();
void resumeLearnMode();
void handleLearnMode();
void buildCapture(JsonObject capture);
const char* modeName(stdAc::opmode_t mode);
const char* fanName(stdAc::fanspeed_t fan);
const char* swingVName(stdAc::swingv_t swing);
const char* swingHName(stdAc::swingh_t swing);
bool verifySignature(const String& message, const String& signature_b64);
String signMessage(const String& message);
int sendAck(const String& commandId, const char* result, const String& error, DynamicJsonDocument* capture = nullptr);
void unlock();

const char* ssid = "<SSID>";
const char* password = "<PASSWORD>";

const char* mqtt_server = "test.mosquitto.org";
const int mqtt_port = 1883;

const char* BASE_URL = "https://gatewiseiot.com";

const int SPACE_ID = <<SPACE_ID>>;
const int CONTROLLER_ID = <<CONTROLLER_ID>>;
const bool HAS_LOCK = true;

String MQTT_TOPIC = "gatewise/spaces/" + String(SPACE_ID) + "/commands";

WiFiClient espClient;
PubSubClient client(espClient);

const int LOCK_PIN = 22;
const int INTERNET_LED_PIN = 32;
const int GREEN_LED_PIN = 26;
const int BUTTON_PIN = 21;
const uint16_t IR_SEND_PIN = 4;
const uint16_t IR_RECV_PIN = 15;

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

const char* BACKEND_PUBLIC_KEY_PEM = "<<BACKEND_PUBLIC_KEY>>";

mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

IRsend irsend(IR_SEND_PIN);
IRac irac(IR_SEND_PIN);
IRrecv irrecv(IR_RECV_PIN, 1024, 50, true);
decode_results irResults;

bool isLearning = false;
String learnCommandId = "";
unsigned long learnDeadline = 0;

const int RECENT_COMMANDS = 16;
String recentCommands[RECENT_COMMANDS];
int recentIndex = 0;
const long MAX_CLOCK_SKEW = 30;

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

  irsend.begin();
  irrecv.setUnknownThreshold(12);

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

  // Default 256 bytes is too small for raw IR commands.
  client.setBufferSize(8192);
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

  if (HAS_LOCK) {
    int buttonReading = digitalRead(BUTTON_PIN);
    if (buttonReading != lastButtonState) {
      lastDebounceTime = millis();
    }
    if (millis() - lastDebounceTime > debounceDelay && buttonReading == LOW && !isUnlocked) {
      unlock();
    }
    lastButtonState = buttonReading;
  }

  handleLearnMode();

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
    String clientId = "GateWiseCtrl_" + String(CONTROLLER_ID);
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

void callback(char* topic, byte* message, unsigned int length) {
  DynamicJsonDocument envelope(length + 512);
  if (deserializeJson(envelope, message, length)) return;

  String payload = envelope["payload"] | "";
  String signature = envelope["signature"] | "";
  if (payload == "" || !verifySignature(payload, signature)) {
    Serial.println("Command rejected: invalid signature");
    return;
  }

  DynamicJsonDocument doc(payload.length() + 1024);
  if (deserializeJson(doc, payload)) return;

  if ((doc["controllerId"] | 0) != CONTROLLER_ID) return;
  if ((doc["v"] | 0) != 1) return;

  String commandId = doc["commandId"] | "";
  String type = doc["type"] | "";
  long issuedAt = doc["issuedAt"] | 0L;
  long expiresAt = doc["expiresAt"] | 0L;
  long now = time(nullptr);

  if (now <= 100000) {
    Serial.println("Command rejected: NTP not synced yet");
    return;
  }
  if (commandId == "" || now > expiresAt || issuedAt > now + MAX_CLOCK_SKEW) {
    Serial.println("Command rejected: expired");
    return;
  }
  if (wasRecentlyExecuted(commandId)) {
    Serial.println("Command rejected: replay");
    return;
  }
  rememberCommand(commandId);

  JsonObject data = doc["data"];

  if (type == "open") {
    if (!HAS_LOCK) {
      sendAck(commandId, "error", "no_lock");
      return;
    }
    // Only unlock after the backend accepted the ack.
    if (sendAck(commandId, "ok", "") == 200) {
      unlock();
    }
  } else if (type == "airConditioner") {
    String error = sendAirConditionerCommand(data["airConditioner"]);
    sendAck(commandId, error == "" ? "ok" : "error", error);
  } else if (type == "ir") {
    String error = sendIrCommand(data["ir"]);
    sendAck(commandId, error == "" ? "ok" : "error", error);
  } else if (type == "learn") {
    startLearnMode(commandId, data["timeoutSec"] | 20);
  } else {
    sendAck(commandId, "error", "unknown_command");
  }
}

bool wasRecentlyExecuted(const String& commandId) {
  for (int i = 0; i < RECENT_COMMANDS; i++) {
    if (recentCommands[i] == commandId) return true;
  }
  return false;
}

void rememberCommand(const String& commandId) {
  recentCommands[recentIndex] = commandId;
  recentIndex = (recentIndex + 1) % RECENT_COMMANDS;
}

String sendAirConditionerCommand(JsonObject airConditioner) {
  decode_type_t protocol = strToDecodeType(airConditioner["protocol"] | "");
  if (!IRac::isProtocolSupported(protocol)) return "unsupported_protocol";

  stdAc::state_t state;
  state.protocol = protocol;
  state.model = airConditioner["model"] | -1;
  state.power = airConditioner["power"] | false;
  state.mode = IRac::strToOpmode(airConditioner["mode"] | "auto");
  state.degrees = airConditioner["degrees"] | 24.0f;
  state.celsius = airConditioner["celsius"] | true;
  state.fanspeed = IRac::strToFanspeed(airConditioner["fanSpeed"] | "auto");
  state.swingv = IRac::strToSwingV(airConditioner["swingVertical"] | "off");
  state.swingh = IRac::strToSwingH(airConditioner["swingHorizontal"] | "off");
  state.turbo = airConditioner["turbo"] | false;
  state.econo = airConditioner["econo"] | false;
  state.quiet = airConditioner["quiet"] | false;
  state.light = airConditioner["light"] | false;
  state.clean = airConditioner["clean"] | false;
  state.filter = airConditioner["filter"] | false;
  state.beep = airConditioner["beep"] | false;
  state.sleep = airConditioner["sleep"] | -1;
  state.clock = -1;

  pauseLearnMode();
  bool sent = irac.sendAc(state, nullptr);
  resumeLearnMode();

  return sent ? "" : "send_failed";
}

String sendIrCommand(JsonObject ir) {
  String protocolName = ir["protocol"] | "";
  bool sent = false;

  pauseLearnMode();

  if (protocolName == "RAW") {
    JsonArray raw = ir["raw"];
    uint16_t length = raw.size();
    if (length == 0) {
      resumeLearnMode();
      return "missing_raw";
    }
    uint16_t* buffer = new uint16_t[length];
    for (uint16_t i = 0; i < length; i++) buffer[i] = raw[i];
    irsend.sendRaw(buffer, length, ir["frequencyKhz"] | 38);
    delete[] buffer;
    sent = true;
  } else {
    decode_type_t protocol = strToDecodeType(protocolName.c_str());
    String code = ir["code"] | "";
    uint16_t bits = ir["bits"] | 0;
    if (protocol == decode_type_t::UNKNOWN || code == "") {
      resumeLearnMode();
      return "unsupported_protocol";
    }
    if (code.startsWith("0x") || code.startsWith("0X")) code = code.substring(2);

    if (hasACState(protocol)) {
      uint16_t nbytes = code.length() / 2;
      uint8_t* state = new uint8_t[nbytes];
      for (uint16_t i = 0; i < nbytes; i++) {
        state[i] = strtoul(code.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
      }
      sent = irsend.send(protocol, state, nbytes);
      delete[] state;
    } else {
      uint64_t value = strtoull(code.c_str(), nullptr, 16);
      sent = irsend.send(protocol, value, bits, ir["repeat"] | 0);
    }
  }

  resumeLearnMode();
  return sent ? "" : "send_failed";
}

void startLearnMode(const String& commandId, int timeoutSec) {
  isLearning = true;
  learnCommandId = commandId;
  learnDeadline = millis() + (unsigned long)timeoutSec * 1000UL;
  irrecv.enableIRIn();
  digitalWrite(GREEN_LED_PIN, HIGH);
  Serial.println("Learn mode: point the remote at the controller and press a button");
}

void stopLearnMode() {
  isLearning = false;
  learnCommandId = "";
  irrecv.disableIRIn();
  if (!isUnlocked) digitalWrite(GREEN_LED_PIN, LOW);
}

void pauseLearnMode() {
  if (isLearning) irrecv.disableIRIn();
}

void resumeLearnMode() {
  if (isLearning) irrecv.enableIRIn();
}

void handleLearnMode() {
  if (!isLearning) return;

  if ((long)(millis() - learnDeadline) >= 0) {
    String commandId = learnCommandId;
    stopLearnMode();
    sendAck(commandId, "error", "no_signal");
    return;
  }

  if (!irrecv.decode(&irResults)) return;

  if (irResults.repeat || irResults.overflow) {
    irrecv.resume();
    return;
  }

  String commandId = learnCommandId;
  DynamicJsonDocument capture(12288);
  buildCapture(capture.to<JsonObject>());
  stopLearnMode();
  sendAck(commandId, "ok", "", &capture);
}

void buildCapture(JsonObject capture) {
  decode_type_t protocol = irResults.decode_type;

  if (protocol == decode_type_t::UNKNOWN) {
    capture["protocol"] = "RAW";
    capture["frequencyKhz"] = 38;
    uint16_t* raw = resultToRawArray(&irResults);
    uint16_t length = getCorrectedRawLength(&irResults);
    JsonArray rawArray = capture.createNestedArray("raw");
    for (uint16_t i = 0; i < length; i++) rawArray.add(raw[i]);
    delete[] raw;
    return;
  }

  capture["protocol"] = typeToString(protocol);
  capture["code"] = resultToHexidecimal(&irResults);
  capture["bits"] = irResults.bits;

  stdAc::state_t state;
  if (IRac::isProtocolSupported(protocol) && IRAcUtils::decodeToState(&irResults, &state)) {
    capture["model"] = state.model;
    JsonObject airConditioner = capture.createNestedObject("airConditioner");
    airConditioner["power"] = state.power && state.mode != stdAc::opmode_t::kOff;
    airConditioner["mode"] = modeName(state.mode);
    airConditioner["degrees"] = state.degrees;
    airConditioner["fanSpeed"] = fanName(state.fanspeed);
    airConditioner["swingVertical"] = swingVName(state.swingv);
    airConditioner["swingHorizontal"] = swingHName(state.swingh);
    airConditioner["turbo"] = state.turbo;
    airConditioner["econo"] = state.econo;
    airConditioner["quiet"] = state.quiet;
    airConditioner["light"] = state.light;
    airConditioner["clean"] = state.clean;
    airConditioner["filter"] = state.filter;
    airConditioner["beep"] = state.beep;
    airConditioner["sleep"] = state.sleep;
  }
}

// Must match the backend enums.
const char* modeName(stdAc::opmode_t mode) {
  switch (mode) {
    case stdAc::opmode_t::kCool: return "Cool";
    case stdAc::opmode_t::kHeat: return "Heat";
    case stdAc::opmode_t::kDry: return "Dry";
    case stdAc::opmode_t::kFan: return "Fan";
    default: return "Auto";
  }
}

const char* fanName(stdAc::fanspeed_t fan) {
  switch (fan) {
    case stdAc::fanspeed_t::kMin: return "Min";
    case stdAc::fanspeed_t::kLow: return "Low";
    case stdAc::fanspeed_t::kMedium: return "Medium";
    case stdAc::fanspeed_t::kMediumHigh:
    case stdAc::fanspeed_t::kHigh: return "High";
    case stdAc::fanspeed_t::kMax: return "Max";
    default: return "Auto";
  }
}

const char* swingVName(stdAc::swingv_t swing) {
  switch (swing) {
    case stdAc::swingv_t::kAuto: return "Auto";
    case stdAc::swingv_t::kHighest: return "Highest";
    case stdAc::swingv_t::kUpperMiddle:
    case stdAc::swingv_t::kHigh: return "High";
    case stdAc::swingv_t::kMiddle: return "Middle";
    case stdAc::swingv_t::kLow: return "Low";
    case stdAc::swingv_t::kLowest: return "Lowest";
    default: return "Off";
  }
}

const char* swingHName(stdAc::swingh_t swing) {
  switch (swing) {
    case stdAc::swingh_t::kAuto: return "Auto";
    case stdAc::swingh_t::kLeftMax: return "LeftMax";
    case stdAc::swingh_t::kLeft: return "Left";
    case stdAc::swingh_t::kMiddle: return "Middle";
    case stdAc::swingh_t::kRight: return "Right";
    case stdAc::swingh_t::kRightMax: return "RightMax";
    case stdAc::swingh_t::kWide: return "Wide";
    default: return "Off";
  }
}

bool verifySignature(const String& message, const String& signature_b64) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  int ret = mbedtls_pk_parse_public_key(&pk,
    (const unsigned char*)BACKEND_PUBLIC_KEY_PEM,
    strlen(BACKEND_PUBLIC_KEY_PEM) + 1);
  if (ret != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }

  unsigned char hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             (const unsigned char*)message.c_str(),
             message.length(), hash);

  unsigned char sig_bin[256];
  size_t sig_len = 0;
  ret = mbedtls_base64_decode(sig_bin, sizeof(sig_bin), &sig_len,
                              (const unsigned char*)signature_b64.c_str(),
                              signature_b64.length());
  if (ret != 0) {
    mbedtls_pk_free(&pk);
    return false;
  }

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
    mbedtls_pk_free(&pk);
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

int sendAck(const String& commandId, const char* result, const String& error, DynamicJsonDocument* capture) {
  long timestamp = time(nullptr);

  if (timestamp <= 100000) {
    Serial.println("NTP not synced yet.");
    return -1;
  }

  DynamicJsonDocument doc(capture ? capture->memoryUsage() + 1024 : 512);
  doc["commandId"] = commandId;
  doc["controllerId"] = CONTROLLER_ID;
  doc["result"] = result;
  if (error != "") doc["error"] = error;
  doc["timestamp"] = timestamp;
  if (capture) doc["capture"] = capture->as<JsonObject>();

  String payload;
  serializeJson(doc, payload);

  String signature = signMessage(payload);
  if (signature == "") return -1;

  DynamicJsonDocument envelope(payload.length() + 1024);
  envelope["payload"] = payload;
  envelope["signature"] = signature;

  String body;
  serializeJson(envelope, body);

  WiFiClientSecure secureClient;
  secureClient.setInsecure();

  HTTPClient http;
  http.begin(secureClient, String(BASE_URL) + "/api/devices/ack");
  http.addHeader("Content-Type", "application/json");

  int code = http.POST(body);
  http.end();

  Serial.print("Ack ");
  Serial.print(result);
  Serial.print(" -> HTTP ");
  Serial.println(code);
  return code;
}

void unlock() {
  isUnlocked = true;
  unlockStartTime = millis();
  digitalWrite(LOCK_PIN, HIGH);
  digitalWrite(GREEN_LED_PIN, HIGH);
}
