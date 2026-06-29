#define BLYNK_TEMPLATE_ID "TMPL6rKVaUGaL"
#define BLYNK_TEMPLATE_NAME "RFID"
#define BLYNK_AUTH_TOKEN "HZ005eSvASwsw5GWWFynPlY51rK21fte"

#include <WiFi.h>
#include <BlynkSimpleEsp32.h>
#include <SPI.h>
#include <MFRC522.h>
#include <Preferences.h>
#include <time.h>

char ssid[] = "ARRAZKA 2 LANTAI 2";
char wifiPass[] = "Razka1109";

constexpr uint8_t RFID_SS_PIN = 5;
constexpr uint8_t RFID_RST_PIN = 22;

constexpr uint8_t LOCK_PIN = 26;        // IN relay
constexpr uint8_t SPEAKER_PIN = 25;     // buzzer
constexpr uint8_t OPEN_LED_PIN = 4;     // LED

constexpr uint8_t RELAY_ACTIVE_LEVEL = LOW;
constexpr uint8_t RELAY_INACTIVE_LEVEL = HIGH;

constexpr unsigned long UNLOCK_DURATION_MS = 5000; // Delay Terbuka
constexpr unsigned long LOCKOUT_DURATION_MS = 30000; // Lama blokir akses
constexpr unsigned long RFID_SCAN_COOLDOWN_MS = 400;
constexpr unsigned long RFID_HEALTHCHECK_INTERVAL_MS = 3000;
constexpr unsigned long DENIED_REPEAT_IGNORE_MS = 3000;
constexpr uint8_t MAX_FAILED_ATTEMPTS = 3; // Batas salah tap sebelum masuk mode lockout
constexpr size_t MAX_UIDS = 20; // Maksimum jumlah UID whitelist yang disimpan.
constexpr unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
constexpr unsigned long WIFI_RETRY_INTERVAL_MS = 10000;
constexpr unsigned long NTP_SYNC_TIMEOUT_MS = 15000;

MFRC522 mfrc522(RFID_SS_PIN, RFID_RST_PIN);
BlynkTimer timer;
Preferences prefs;

bool lockOpen = false;
unsigned long unlockStartedAt = 0;
unsigned long lastScanAt = 0;
unsigned long lastRfidHealthcheckAt = 0;
unsigned long lockoutUntil = 0;
uint8_t failedAttempts = 0;
String lastDeniedUid = "";
unsigned long lastDeniedAt = 0;
bool wifiLoggedConnected = false;
bool blynkLoggedConnected = false;
unsigned long lastWifiRetryAt = 0;

// UID 
const char *DEFAULT_ALLOWED_UIDS[] = {
  "3C695E22",
  "C4750589",
  "D6D96CD9",
  "2929B9A2",
  "097CB8A2"
};
constexpr size_t DEFAULT_ALLOWED_UIDS_COUNT = sizeof(DEFAULT_ALLOWED_UIDS) / sizeof(DEFAULT_ALLOWED_UIDS[0]);

// Nama untuk tampilan dashboard
struct CardOwner {
  const char *uid;
  const char *name;
};

const CardOwner CARD_OWNERS[] = {
  {"3C695E22", "Sarah"},
  {"C4750589", "Asep"},
  {"D6D96CD9", "Nita"},
  {"2929B9A2", "Sarah"},
  {"097CB8A2", "Admin"}
};
constexpr size_t CARD_OWNERS_COUNT = sizeof(CARD_OWNERS) / sizeof(CARD_OWNERS[0]);

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

String ownerNameFromUid(const String &uid) {
  for (size_t i = 0; i < CARD_OWNERS_COUNT; i++) {
    if (uid == CARD_OWNERS[i].uid) return CARD_OWNERS[i].name;
  }
  return "Tidak dikenal";
}

void saveUidsToNvs() {
  String data;
  for (size_t i = 0; i < allowedCount; i++) {
    if (i > 0) data += ",";
    data += allowedUids[i];
  }
  prefs.putString("uids", data);
}

void loadUidsFromNvs() {
  allowedCount = 0;
  String data = prefs.getString("uids", "");

  if (data.length() == 0) return;

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

bool addUidIfMissingNoSave(const String &rawUid) {
  String uid = normalizeUid(rawUid);
  if (!isValidUid(uid) || isUidAllowed(uid) || allowedCount >= MAX_UIDS) return false;
  allowedUids[allowedCount++] = uid;
  return true;
}

bool addUid(const String &rawUid) {
  if (!addUidIfMissingNoSave(rawUid)) return false;
  saveUidsToNvs();
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
      saveUidsToNvs();
      return true;
    }
  }
  return false;
}

void mergeDefaultUidsToNvs() {
  bool changed = false;
  for (size_t i = 0; i < DEFAULT_ALLOWED_UIDS_COUNT; i++) {
    if (addUidIfMissingNoSave(DEFAULT_ALLOWED_UIDS[i])) changed = true;
  }
  if (changed) saveUidsToNvs();
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

void printWhitelistToSerial() {
  Serial.print("Whitelist aktif (");
  Serial.print(allowedCount);
  Serial.println("):");
  for (size_t i = 0; i < allowedCount; i++) {
    Serial.print("- ");
    Serial.println(allowedUids[i]);
  }
}

void getDateTimeStrings(String &timeStr, String &dateStr) {
  struct tm t;
  if (!getLocalTime(&t, 100)) {
    timeStr = "--:--:--";
    dateStr = "--/--/----";
    return;
  }

  char timeBuf[16];
  char dateBuf[24];
  strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &t);
  strftime(dateBuf, sizeof(dateBuf), "%d-%m-%Y", &t);
  timeStr = timeBuf;
  dateStr = dateBuf;
}

bool syncClockWithRetry(unsigned long timeoutMs) {
  unsigned long started = millis();
  struct tm t;
  while (millis() - started < timeoutMs) {
    if (getLocalTime(&t, 200)) {
      Serial.println("NTP sync berhasil.");
      return true;
    }
    delay(300);
    Serial.print(".");
  }
  Serial.println();
  Serial.println("NTP sync gagal, timestamp akan tampil '--' sampai waktu tersinkron.");
  return false;
}

void sendAccessCardToDashboard(const String &statusText, const String &uid) {
  if (!Blynk.connected()) return;

  String jam, tanggal;
  getDateTimeStrings(jam, tanggal);
  String nama = ownerNameFromUid(uid);

  String card =
      "Nama : " + nama + "\n" +
      "Status : " + statusText + "\n" +
      "Uid : " + uid + "\n" +
      "Jam akses : " + jam + "\n" +
      "Tanggal : " + tanggal;

  Blynk.virtualWrite(V4, card);

  Blynk.virtualWrite(V5, nama);
  Blynk.virtualWrite(V6, statusText);
  Blynk.virtualWrite(V7, uid);
  Blynk.virtualWrite(V8, jam);
  Blynk.virtualWrite(V9, tanggal);

  Blynk.virtualWrite(V11, tanggal + " " + jam);
}

void playToneMs(uint16_t freq, uint16_t durationMs) {
  tone(SPEAKER_PIN, freq, durationMs);
  delay(durationMs + 20);
  noTone(SPEAKER_PIN);
}

void playUnlockSound() {
  playToneMs(1200, 120);
  playToneMs(1700, 140);
}

void playLockSound() {
  playToneMs(1700, 120);
  playToneMs(1200, 160);
}

void playDeniedSound() {
  for (uint8_t i = 0; i < 3; i++) {
    playToneMs(500, 100);
    delay(50);
  }
}

void resetRfidAfterRead() {
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  mfrc522.PCD_AntennaOff();
  delay(3);
  mfrc522.PCD_AntennaOn();
  delay(30);
}

void keepRfidHealthy() {
  if (millis() - lastRfidHealthcheckAt < RFID_HEALTHCHECK_INTERVAL_MS) return;
  lastRfidHealthcheckAt = millis();

  byte version = mfrc522.PCD_ReadRegister(MFRC522::VersionReg);
  if (version == 0x00 || version == 0xFF) {
    Serial.println("RFID healthcheck: re-init RC522...");
    mfrc522.PCD_Init();
  }
}

void setRelay(bool on) {
  digitalWrite(LOCK_PIN, on ? RELAY_ACTIVE_LEVEL : RELAY_INACTIVE_LEVEL);
}

void setLock(bool open) {
  lockOpen = open;
  setRelay(open);
  digitalWrite(OPEN_LED_PIN, open ? HIGH : LOW);
  if (open) {
    playUnlockSound();
  } else {
    playLockSound();
  }

  if (Blynk.connected()) {
    Blynk.virtualWrite(V0, open ? 1 : 0);
    Blynk.virtualWrite(V1, open ? "Solenoid: TERBUKA (UNLOCK)" : "Solenoid: TERTUTUP (LOCK)");
  }
}

void failAccess(const String &uid, const String &message, const String &eventMessage) {
  playDeniedSound();

  bool countAsNewFailedAttempt = true;
  if (uid == lastDeniedUid && (millis() - lastDeniedAt) < DENIED_REPEAT_IGNORE_MS) {
    countAsNewFailedAttempt = false;
  }

  if (countAsNewFailedAttempt) {
    failedAttempts++;
    lastDeniedUid = uid;
    lastDeniedAt = millis();
  }

  if (Blynk.connected()) {
    Blynk.virtualWrite(V4, message);
    Blynk.logEvent("akses_ditolak", eventMessage);
    sendAccessCardToDashboard("ditolak", uid);
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

void notifyLockoutAttempt(const String &uid) {
  unsigned long remainMs = lockoutUntil > millis() ? (lockoutUntil - millis()) : 0;
  unsigned long remainSec = (remainMs + 999) / 1000;

  Serial.print("LOCKOUT aktif, sisa ");
  Serial.print(remainSec);
  Serial.println(" detik.");

  playDeniedSound();

  if (Blynk.connected()) {
    String msg = "Akses diblokir sementara. Coba lagi " + String(remainSec) + " detik.";
    Blynk.virtualWrite(V4, msg);
    Blynk.logEvent("akses_ditolak", "Percobaan saat lockout aktif UID: " + uid);
    sendAccessCardToDashboard("ditolak", uid);
  }
}

void handleRFID() {
  if (millis() - lastScanAt < RFID_SCAN_COOLDOWN_MS) return;
  if (!mfrc522.PICC_IsNewCardPresent()) return;
  if (!mfrc522.PICC_ReadCardSerial()) {
    // paksa init ulang.
    mfrc522.PCD_Init();
    delay(20);
    return;
  }
  lastScanAt = millis();

  String uid = uidToString(mfrc522.uid);
  Serial.print("Card UID: ");
  Serial.println(uid);

  if (millis() < lockoutUntil) {
    notifyLockoutAttempt(uid);
    resetRfidAfterRead();
    return;
  }

  if (isUidAllowed(uid)) {
    Serial.println("===== TAP-IN BERHASIL =====");
    Serial.print("UID kartu : ");
    Serial.println(uid);
    Serial.print("Relay     : ON (unlock ");
    Serial.print(UNLOCK_DURATION_MS / 1000);
    Serial.println(" detik)");
    Serial.println("===========================");

    if (Blynk.connected()) {
      Blynk.virtualWrite(V4, "Akses diterima: " + uid);
      sendAccessCardToDashboard("diterima", uid);
    }
    setLock(true);
    unlockStartedAt = millis();
    failedAttempts = 0;
    lastDeniedUid = "";
    lastDeniedAt = 0;
  } else {
    Serial.println("Akses ditolak.");
    Serial.print("UID ");
    Serial.print(uid);
    Serial.println(" tidak ada di whitelist.");
    failAccess(uid, "Akses ditolak: " + uid, "UID tidak terdaftar: " + uid);
  }

  resetRfidAfterRead();
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
    saveUidsToNvs();
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
    Blynk.virtualWrite(V4, addUid(uid) ? ("UID ditambahkan: " + normalizeUid(uid)) : "Gagal tambah UID.");
    return;
  }
  if (action == "DEL") {
    Blynk.virtualWrite(V4, removeUid(uid) ? ("UID dihapus: " + normalizeUid(uid)) : "UID tidak ditemukan.");
    return;
  }

  Blynk.virtualWrite(V4, "Perintah tidak valid. Pakai: ADD UID, DEL UID, LIST, CLEAR");
}

void connectNetworkNonBlocking() {
  if (WiFi.status() != WL_CONNECTED) {
    if (wifiLoggedConnected) {
      wifiLoggedConnected = false;
      blynkLoggedConnected = false;
      Serial.println("[NET] WiFi terputus.");
    }
    if (millis() - lastWifiRetryAt >= WIFI_RETRY_INTERVAL_MS) {
      Serial.print("[NET] Coba reconnect WiFi ke SSID: ");
      Serial.println(ssid);
      WiFi.disconnect();
      delay(100);
      WiFi.begin(ssid, wifiPass);
      lastWifiRetryAt = millis();
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
  Serial.println("Smart Safe RFID ESP32 starting...");

  pinMode(LOCK_PIN, OUTPUT);
  setRelay(false); // default relay OFF

  pinMode(OPEN_LED_PIN, OUTPUT);
  digitalWrite(OPEN_LED_PIN, LOW);

  pinMode(SPEAKER_PIN, OUTPUT);
  noTone(SPEAKER_PIN);

  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("RFID RC522 siap.");
  byte version = mfrc522.PCD_ReadRegister(MFRC522::VersionReg);
  Serial.print("RC522 VersionReg: 0x");
  Serial.println(version, HEX);
  if (version == 0x00 || version == 0xFF) {
    Serial.println("WARNING: RC522 tidak terdeteksi. Cek wiring SDA/SCK/MOSI/MISO/RST dan 3.3V.");
  }

  prefs.begin("safe-rfid", false);
  loadUidsFromNvs();
  mergeDefaultUidsToNvs();
  printWhitelistToSerial();

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
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
  }

  // UTC+7 (WIB)
  configTime(7 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("Sinkronisasi NTP");
  syncClockWithRetry(NTP_SYNC_TIMEOUT_MS);

  Blynk.config(BLYNK_AUTH_TOKEN);
  Blynk.connect(1000);

  setLock(false);

  timer.setInterval(3000, connectNetworkNonBlocking);
}

void loop() {
  Blynk.run();
  timer.run();
  keepRfidHealthy();
  handleRFID();
  
  if (lockOpen && (millis() - unlockStartedAt >= UNLOCK_DURATION_MS)) {
    Serial.println("Waktu unlock habis, lock ditutup.");
    setLock(false);
  }
}
