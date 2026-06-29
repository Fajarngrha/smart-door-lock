#define BLYNK_TEMPLATE_ID "TMPL64inXV6Wh"
#define BLYNK_TEMPLATE_NAME "Smart Door Loock"
#define BLYNK_AUTH_TOKEN "M0ckov-Ibf7G6JVVl0lv4asKNmKEEsVy"

#include <ESP8266WiFi.h>
#include <BlynkSimpleEsp8266.h>
#include <SPI.h>
#include <MFRC522.h>
#include <EEPROM.h>

// -------------------- WiFi --------------------
char ssid[] = "fajar";
char wifiPass[] = "1234567890";

// -------------------- RC522 pins (NodeMCU/Wemos D1 mini) --------------------
// RC522 SCK -> D5, MISO -> D6, MOSI -> D7 (hardware SPI)
constexpr uint8_t RFID_SS_PIN = 4;   // GPIO4 (D2)  SDA/SS
constexpr uint8_t RFID_RST_PIN = 0;  // GPIO0 (D3)  RST

// -------------------- Solenoid + door sensor + alarm --------------------
constexpr uint8_t LOCK_PIN = 5;           // GPIO5 (D1) relay/MOSFET input
constexpr uint8_t DOOR_SENSOR_PIN = 16;   // GPIO16 (D0) reed switch INPUT_PULLUP
constexpr uint8_t STATUS_LED_PIN = LED_BUILTIN; // biasanya GPIO2 (D4, active LOW)
constexpr uint8_t BUZZER_PIN = 15;        // GPIO15 (D8) buzzer via transistor driver
// Sesuaikan bila relay module kamu tipe active LOW (umum di pasaran)
constexpr uint8_t RELAY_ACTIVE_LEVEL = LOW;
constexpr uint8_t RELAY_INACTIVE_LEVEL = HIGH;

constexpr unsigned long UNLOCK_DURATION_MS = 5000;
constexpr unsigned long BLYNK_STATUS_INTERVAL_MS = 1000;
constexpr unsigned long LOCKOUT_DURATION_MS = 30000;
constexpr uint8_t MAX_FAILED_ATTEMPTS = 3;
constexpr size_t MAX_UIDS = 20;
constexpr unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;

// EEPROM for whitelist persistence
constexpr size_t EEPROM_SIZE = 512;
constexpr int EEPROM_LEN_ADDR = 0;   // 2 bytes
constexpr int EEPROM_DATA_ADDR = 2;  // CSV string start

MFRC522 mfrc522(RFID_SS_PIN, RFID_RST_PIN);
BlynkTimer timer;
bool wifiLoggedConnected = false;
bool blynkLoggedConnected = false;
unsigned long lastWifiRetryAt = 0;

bool lockOpen = false;
bool lastDoorOpen = false;
bool forcedOpenAlertSent = false;
unsigned long unlockStartedAt = 0;
unsigned long lockoutUntil = 0;
uint8_t failedAttempts = 0;

const char *DEFAULT_ALLOWED_UIDS[] = {
  "A1B2C3D4",
  "11223344",
  "3C695E22",
  "C4750589",
  "D6D96CD9",
  "2929B9A2",
  "097CB8A2"



};
constexpr size_t DEFAULT_ALLOWED_UIDS_COUNT = sizeof(DEFAULT_ALLOWED_UIDS) / sizeof(DEFAULT_ALLOWED_UIDS[0]);
String allowedUids[MAX_UIDS];
size_t allowedCount = 0;

String normalizeUid(String uid) {
  uid.replace(" ", "");
  uid.replace(":", "");
  uid.replace("-", "");
  uid.trim();
  uid.toUpperCase();
  return uid;
}

bool isHexChar(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
}

bool isValidUid(const String &uid) {
  if (uid.length() < 8 || uid.length() > 20 || (uid.length() % 2 != 0)) return false;
  for (size_t i = 0; i < uid.length(); i++) {
    if (!isHexChar(uid[i])) return false;
  }
  return true;
}

String uidToString(const MFRC522::Uid &uid) {
  String out;
  for (byte i = 0; i < uid.size; i++) {
    if (uid.uidByte[i] < 0x10) out += "0";
    out += String(uid.uidByte[i], HEX);
  }
  out.toUpperCase();
  return out;
}

bool isUidAllowed(const String &uid) {
  for (size_t i = 0; i < allowedCount; i++) {
    if (uid == allowedUids[i]) return true;
  }
  return false;
}

void writeWhitelistRaw(const String &data) {
  uint16_t len = data.length();
  uint16_t maxLen = EEPROM_SIZE - EEPROM_DATA_ADDR;
  if (len > maxLen) len = maxLen;

  EEPROM.write(EEPROM_LEN_ADDR, len & 0xFF);
  EEPROM.write(EEPROM_LEN_ADDR + 1, (len >> 8) & 0xFF);
  for (uint16_t i = 0; i < len; i++) {
    EEPROM.write(EEPROM_DATA_ADDR + i, data[i]);
  }
  if (len < maxLen) {
    EEPROM.write(EEPROM_DATA_ADDR + len, '\0');
  }
  EEPROM.commit();
}

String readWhitelistRaw() {
  uint16_t len = EEPROM.read(EEPROM_LEN_ADDR) | (EEPROM.read(EEPROM_LEN_ADDR + 1) << 8);
  uint16_t maxLen = EEPROM_SIZE - EEPROM_DATA_ADDR;
  if (len == 0 || len > maxLen) return "";

  String data;
  data.reserve(len);
  for (uint16_t i = 0; i < len; i++) {
    data += char(EEPROM.read(EEPROM_DATA_ADDR + i));
  }
  return data;
}

void saveUidsToStorage() {
  String data;
  for (size_t i = 0; i < allowedCount; i++) {
    if (i > 0) data += ",";
    data += allowedUids[i];
  }
  writeWhitelistRaw(data);
}

void loadUidsFromStorage() {
  allowedCount = 0;
  String data = readWhitelistRaw();

  if (data.length() == 0) {
    for (size_t i = 0; i < DEFAULT_ALLOWED_UIDS_COUNT && i < MAX_UIDS; i++) {
      allowedUids[allowedCount++] = DEFAULT_ALLOWED_UIDS[i];
    }
    saveUidsToStorage();
    return;
  }

  int start = 0;
  while (start < data.length() && allowedCount < MAX_UIDS) {
    int comma = data.indexOf(',', start);
    if (comma < 0) comma = data.length();
    String uid = normalizeUid(data.substring(start, comma));
    if (isValidUid(uid) && !isUidAllowed(uid)) {
      allowedUids[allowedCount++] = uid;
    }
    start = comma + 1;
  }
}

bool addUid(const String &rawUid) {
  String uid = normalizeUid(rawUid);
  if (!isValidUid(uid) || isUidAllowed(uid) || allowedCount >= MAX_UIDS) return false;
  allowedUids[allowedCount++] = uid;
  saveUidsToStorage();
  return true;
}

bool addUidIfMissingNoSave(const String &rawUid) {
  String uid = normalizeUid(rawUid);
  if (!isValidUid(uid) || isUidAllowed(uid) || allowedCount >= MAX_UIDS) return false;
  allowedUids[allowedCount++] = uid;
  return true;
}

bool removeUid(const String &rawUid) {
  String uid = normalizeUid(rawUid);
  for (size_t i = 0; i < allowedCount; i++) {
    if (allowedUids[i] == uid) {
      for (size_t j = i; j + 1 < allowedCount; j++) {
        allowedUids[j] = allowedUids[j + 1];
      }
      allowedCount--;
      saveUidsToStorage();
      return true;
    }
  }
  return false;
}

String buildUidList() {
  if (allowedCount == 0) return "Whitelist kosong";
  String list = "UID aktif: ";
  for (size_t i = 0; i < allowedCount; i++) {
    if (i > 0) list += ", ";
    list += allowedUids[i];
  }
  return list;
}

void mergeDefaultUidsToStorage() {
  bool changed = false;
  for (size_t i = 0; i < DEFAULT_ALLOWED_UIDS_COUNT; i++) {
    if (addUidIfMissingNoSave(DEFAULT_ALLOWED_UIDS[i])) {
      changed = true;
    }
  }
  if (changed) saveUidsToStorage();
}

void printWhitelistToSerial() {
  Serial.print("Whitelist aktif (");
  Serial.print(allowedCount);
  Serial.println("):");
  for (size_t i = 0; i < allowedCount; i++) {
    Serial.print("- ");
    Serial.println(allowedUids[i]);
  }
}

bool isDoorOpen() {
  return digitalRead(DOOR_SENSOR_PIN) == HIGH;
}

void setStatusLed(bool on) {
  digitalWrite(STATUS_LED_PIN, on ? LOW : HIGH); // LED_BUILTIN active LOW
}

void pulseBuzzer(uint16_t ms) {
  digitalWrite(BUZZER_PIN, HIGH);
  delay(ms);
  digitalWrite(BUZZER_PIN, LOW);
}

void successAlarm() {
  setStatusLed(true);
  pulseBuzzer(100);
  setStatusLed(false);
}

void deniedAlarm() {
  for (uint8_t i = 0; i < 3; i++) {
    setStatusLed(true);
    pulseBuzzer(120);
    setStatusLed(false);
    delay(80);
  }
}

void setRelay(bool on) {
  digitalWrite(LOCK_PIN, on ? RELAY_ACTIVE_LEVEL : RELAY_INACTIVE_LEVEL);
}

void setLock(bool open) {
  lockOpen = open;
  // open=true -> relay ON untuk memberi daya ke solenoid unlock
  setRelay(open);

  if (Blynk.connected()) {
    Blynk.virtualWrite(V0, open ? 1 : 0);
    Blynk.virtualWrite(V1, open ? "Solenoid: TERBUKA (UNLOCK)" : "Solenoid: TERTUTUP (LOCK)");
  }
}

const char *wifiStatusText(wl_status_t status) {
  switch (status) {
    case WL_IDLE_STATUS: return "IDLE";
    case WL_NO_SSID_AVAIL: return "SSID TIDAK DITEMUKAN";
    case WL_SCAN_COMPLETED: return "SCAN COMPLETED";
    case WL_CONNECTED: return "CONNECTED";
    case WL_CONNECT_FAILED: return "PASSWORD SALAH / AUTH GAGAL";
    case WL_CONNECTION_LOST: return "KONEKSI TERPUTUS";
    case WL_DISCONNECTED: return "DISCONNECTED";
    default: return "UNKNOWN";
  }
}

void startWifiConnect() {
  Serial.print("[NET] Coba konek WiFi ke SSID: ");
  Serial.println(ssid);
  WiFi.disconnect();
  delay(100);
  WiFi.begin(ssid, wifiPass);
  lastWifiRetryAt = millis();
}

void sendDoorStatus() {
  bool doorOpen = isDoorOpen();
  if (doorOpen != lastDoorOpen) {
    lastDoorOpen = doorOpen;
    if (Blynk.connected()) {
      Blynk.virtualWrite(V2, doorOpen ? 1 : 0);
      Blynk.virtualWrite(V3, doorOpen ? "Pintu TERBUKA" : "Pintu TERTUTUP");
    }
  }
}

void monitorForcedDoorOpen() {
  bool doorOpen = isDoorOpen();
  if (!lockOpen && doorOpen && !forcedOpenAlertSent) {
    forcedOpenAlertSent = true;
    if (Blynk.connected()) {
      Blynk.virtualWrite(V4, "ALERT: pintu terbuka saat lock aktif");
      Blynk.logEvent("pintu_dipaksa", "Pintu terdeteksi terbuka saat kondisi lock aktif.");
    }
  }
  if (!doorOpen) forcedOpenAlertSent = false;
}

void failAccess(const String &message, const String &eventMessage) {
  deniedAlarm();
  failedAttempts++;
  if (Blynk.connected()) {
    Blynk.virtualWrite(V4, message);
    Blynk.logEvent("akses_ditolak", eventMessage);
  }

  if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
    lockoutUntil = millis() + LOCKOUT_DURATION_MS;
    failedAttempts = 0;
    if (Blynk.connected()) {
      Blynk.virtualWrite(V4, "LOCKOUT 30 detik karena terlalu banyak gagal.");
      Blynk.logEvent("akses_ditolak", "Lockout aktif 30 detik karena percobaan gagal berulang.");
    }
  }
}

void handleRFID() {
  if (!mfrc522.PICC_IsNewCardPresent()) return;
  if (!mfrc522.PICC_ReadCardSerial()) return;

  String uid = uidToString(mfrc522.uid);
  Serial.print("Card UID: ");
  Serial.println(uid);

  if (millis() < lockoutUntil) {
    failAccess("Akses diblokir sementara (lockout aktif).", "Percobaan saat lockout aktif UID: " + uid);
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return;
  }

  if (isUidAllowed(uid)) {
    Serial.println("Akses diterima, membuka lock.");
    Serial.println("===== TAP-IN BERHASIL =====");
    Serial.print("UID kartu : ");
    Serial.println(uid);
    Serial.print("Relay     : ON (unlock ");
    Serial.print(UNLOCK_DURATION_MS / 1000);
    Serial.println(" detik)");
    Serial.println("===========================");
    successAlarm();
    if (Blynk.connected()) {
      Blynk.virtualWrite(V4, "Akses diterima: " + uid);
    }
    setLock(true);
    unlockStartedAt = millis();
    failedAttempts = 0;
  } else {
    Serial.println("Akses ditolak.");
    Serial.print("UID ");
    Serial.print(uid);
    Serial.println(" tidak ada di whitelist.");
    failAccess("Akses ditolak: " + uid, "UID tidak terdaftar: " + uid);
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

BLYNK_WRITE(V10) {
  String command = param.asStr();
  command.trim();
  String upper = command;
  upper.toUpperCase();

  if (upper == "LIST") {
    Blynk.virtualWrite(V4, buildUidList());
    return;
  }
  if (upper == "CLEAR") {
    allowedCount = 0;
    saveUidsToStorage();
    Blynk.virtualWrite(V4, "Whitelist dikosongkan.");
    return;
  }

  int sep = command.indexOf(' ');
  if (sep < 0) {
    Blynk.virtualWrite(V4, "Perintah tidak valid. Format: ADD UID / DEL UID / LIST / CLEAR");
    return;
  }

  String action = command.substring(0, sep);
  String uid = command.substring(sep + 1);
  action.toUpperCase();

  if (action == "ADD") {
    if (addUid(uid)) {
      Blynk.virtualWrite(V4, "UID ditambahkan: " + normalizeUid(uid));
    } else {
      Blynk.virtualWrite(V4, "Gagal tambah UID (invalid/sudah ada/penuh).");
    }
    return;
  }
  if (action == "DEL") {
    if (removeUid(uid)) {
      Blynk.virtualWrite(V4, "UID dihapus: " + normalizeUid(uid));
    } else {
      Blynk.virtualWrite(V4, "UID tidak ditemukan.");
    }
    return;
  }

  Blynk.virtualWrite(V4, "Perintah tidak valid. Pakai: ADD UID, DEL UID, LIST, CLEAR");
}

void connectNetworkNonBlocking() {
  wl_status_t wstat = WiFi.status();
  if (wstat != WL_CONNECTED) {
    if (wifiLoggedConnected) {
      wifiLoggedConnected = false;
      blynkLoggedConnected = false;
      Serial.println("[NET] WiFi terputus.");
    }

    if (millis() - lastWifiRetryAt >= WIFI_RETRY_INTERVAL_MS) {
      Serial.print("[NET] WiFi status: ");
      Serial.println(wifiStatusText(wstat));
      startWifiConnect();
    }
    return;
  }

  if (!wifiLoggedConnected) {
    wifiLoggedConnected = true;
    Serial.print("[NET] WiFi connected, IP: ");
    Serial.println(WiFi.localIP());
  }

  if (!Blynk.connected()) {
    if (Blynk.connect(1000)) {
      blynkLoggedConnected = true;
      Serial.println("[NET] Blynk connected.");
      Blynk.virtualWrite(V4, "Device online: RFID siap.");
      Blynk.virtualWrite(V2, lastDoorOpen ? 1 : 0);
      Blynk.virtualWrite(V3, lastDoorOpen ? "Pintu TERBUKA" : "Pintu TERTUTUP");
      Blynk.virtualWrite(V0, lockOpen ? 1 : 0);
      Blynk.virtualWrite(V1, lockOpen ? "Solenoid: TERBUKA (UNLOCK)" : "Solenoid: TERTUTUP (LOCK)");
      Blynk.virtualWrite(V4, buildUidList());
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("Smart Safe RFID ESP8266 starting...");

  pinMode(LOCK_PIN, OUTPUT);
  // Default relay OFF saat boot agar tidak tiba-tiba unlock
  setRelay(false);

  pinMode(DOOR_SENSOR_PIN, INPUT_PULLUP);
  pinMode(STATUS_LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  setStatusLed(false);
  digitalWrite(BUZZER_PIN, LOW);

  EEPROM.begin(EEPROM_SIZE);
  loadUidsFromStorage();
  mergeDefaultUidsToStorage();
  printWhitelistToSerial();

  SPI.begin(); // SCK=D5, MISO=D6, MOSI=D7
  mfrc522.PCD_Init();
  Serial.println("RFID RC522 siap (ESP8266).");
  byte version = mfrc522.PCD_ReadRegister(MFRC522::VersionReg);
  Serial.print("RC522 VersionReg: 0x");
  Serial.println(version, HEX);
  if (version == 0x00 || version == 0xFF) {
    Serial.println("WARNING: RC522 tidak terdeteksi. Cek wiring SDA/SCK/MOSI/MISO/RST dan 3.3V.");
  }

  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  WiFi.begin(ssid, wifiPass);
  Serial.print("Connecting WiFi");
  unsigned long started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < WIFI_CONNECT_TIMEOUT_MS) {
    delay(300);
    Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("WiFi OK. IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("WiFi belum terhubung, RFID tetap berjalan (mode offline).");
    Serial.print("Detail status WiFi: ");
    Serial.println(wifiStatusText(WiFi.status()));
  }

  Blynk.config(BLYNK_AUTH_TOKEN);
  Blynk.connect(1000);

  setLock(false);
  lastDoorOpen = isDoorOpen();

  timer.setInterval(BLYNK_STATUS_INTERVAL_MS, sendDoorStatus);
  timer.setInterval(500, monitorForcedDoorOpen);
  timer.setInterval(3000, connectNetworkNonBlocking);
}

void loop() {
  Blynk.run();
  timer.run();
  handleRFID();

  if (lockOpen && (millis() - unlockStartedAt >= UNLOCK_DURATION_MS)) {
    Serial.println("Waktu unlock habis, lock ditutup.");
    setLock(false);
  }
}
