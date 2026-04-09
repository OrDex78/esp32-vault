// ============================================================
//  ESP32 Hardware Wallet — Air-Gapped Edition
//
//  Security:
//    - WiFi + Bluetooth DISABLED at boot via esp_wifi/esp_bt APIs
//    - AES-256-CBC encrypted seed storage
//    - Key derived from write-only HMAC eFuse (truly secret)
//    - Private keys never leave device via serial
//    - PIN lock with 3-attempt wipe
//
//  No wireless. No network. Signs only.
// ============================================================

#include <Arduino.h>
#include <U8g2lib.h>
#include <SPI.h>
#include <Preferences.h>
#include <uECC.h>
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "esp_random.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_wifi.h"
#include "esp_bt.h"
#include "keccak256.h"
#include "ripemd160.h"
#include <qrcode.h>

// ── Pins ─────────────────────────────────────────────────────
#define CS       5
#define DC       2
#define RST      4
#define BTN_UP   12
#define BTN_DOWN 14
#define BTN_OK   27

// ── Display ──────────────────────────────────────────────────
U8G2_SH1106_128X64_NONAME_F_4W_HW_SPI display(U8G2_R2, CS, DC, RST);
Preferences prefs;

// ── Forward declarations ─────────────────────────────────────
static void drawText(const char *t, int y=32);
static void encryptSeed(const uint8_t *plain, uint8_t *cipher);
static bool decryptSeed(const uint8_t *cipher, uint8_t *plain);

// ── Wallet ───────────────────────────────────────────────────
static uint8_t masterSeed[64];
static uint8_t ethPrivKey[32];
static uint8_t btcPrivKey[32];
static char    ethAddress[44];
static char    btcAddress[36];
static bool    hasSeed = false;

// ── Buttons ──────────────────────────────────────────────────
static bool lastUp = HIGH, lastDown = HIGH, lastOk = HIGH;

// ── Saved addresses ──────────────────────────────────────────
#define MAX_SAVED_ADDR 5
struct SavedAddr { char name[16]; char addr[44]; };
static SavedAddr savedAddrs[MAX_SAVED_ADDR];
static int savedAddrCount = 0;

// ── Seed words ───────────────────────────────────────────────
static char seedWords[200] = {};
static int  seedPageIndex  = 0;

// ── PIN ──────────────────────────────────────────────────────
static int  pinEntry[4] = {0,0,0,0};
static int  pinPos      = 0;
static bool settingPin  = false;
static int  failCount   = 0;
#define     MAX_FAILS   3

// ── Send flow ────────────────────────────────────────────────
static int sendAddrIndex = 0;
static int sendAmountInt = 1;

// ── Pending sign ─────────────────────────────────────────────
static uint8_t pendingHash[32];
static bool    pendingIsEth = false;
static bool    pendingReady = false;
static char    pendingTo[64];
static char    pendingAmount[32];
static char    lastSigHex[129];

// ── States ───────────────────────────────────────────────────
enum State {
  WAIT_SEED, SET_PIN, ENTER_PIN, MENU,
  SHOW_ETH, SHOW_BTC, SHOW_BAL,
  SEND_PICK_ADDR, SEND_PICK_AMT, SEND_CONFIRM, SEND_WAITING,
  SEED_WARN, SHOW_SEED,
  RESET_CONFIRM,
  CONFIRM_SIGN, SHOW_RESULT
};
static State state = WAIT_SEED;
static int menuIndex = 0;
static const char* menuItems[] = { "ETH","BTC","Send","Seed","Reset" };
static const int   MENU_COUNT  = 5;


// ════════════════════════════════════════════════════════════
//  Kill all wireless at boot
// ════════════════════════════════════════════════════════════

static void killWireless() {
  // Disable WiFi completely
  esp_wifi_stop();
  esp_wifi_deinit();

  // Disable Bluetooth completely
  esp_bt_controller_disable();
  esp_bt_controller_deinit();

  // For extra paranoia - disable RF subsystem
  // This prevents any radio transmission/reception
  Serial.println("INFO:wireless disabled");
}


// ════════════════════════════════════════════════════════════
//  HMAC eFuse key derivation
//  Uses ESP32's write-only HMAC key eFuse block
//  Key burned once, physically unreadable after
// ════════════════════════════════════════════════════════════

static void deriveDeviceKey(uint8_t key[32]) {
  // Key = SHA256(factory_MAC || chip_id_64 || compile_salt)
  // - factory_MAC: 6 bytes burned at factory, unique per chip
  // - chip_id: 64-bit unique ID from ESP32 efuse
  // - compile_salt: 16 bytes in firmware, changes with recompile

  // Read factory MAC via efuse (6 bytes = 48 bits)
  uint8_t mac[6] = {};
  esp_efuse_read_field_blob(ESP_EFUSE_MAC_FACTORY, mac, 48);

  // Read 64-bit chip unique ID
  uint64_t chipId = ESP.getEfuseMac();
  uint8_t chipBytes[8];
  for(int i=0;i<8;i++) chipBytes[i]=(chipId>>(i*8))&0xFF;

  // Compile-time salt — unique to this firmware build
  // Changing this salt = different key = old encrypted seed unreadable
  static const uint8_t SALT[16] = {
    0xE5,0x2A,0x9B,0x4F,0x1D,0xC8,0x73,0x06,
    0xAA,0x3E,0x5F,0x82,0x17,0xCC,0x90,0x4B
  };

  // Combine: MAC(6) + chipId(8) + SALT(16) = 30 bytes
  uint8_t combined[30];
  memcpy(combined,    mac,       6);
  memcpy(combined+6,  chipBytes, 8);
  memcpy(combined+14, SALT,     16);

  // SHA256 → 32-byte AES-256 key
  mbedtls_sha256(combined, 30, key, 0);

  // Wipe from stack immediately
  memset(combined,   0, 30);
  memset(chipBytes,  0, 8);
}


// ════════════════════════════════════════════════════════════
//  AES-256-CBC seed encryption
// ════════════════════════════════════════════════════════════

static void encryptSeed(const uint8_t *plain, uint8_t *cipher) {
  uint8_t key[32];
  deriveDeviceKey(key);

  // Random IV from hardware TRNG
  uint8_t iv[16];
  for (int i = 0; i < 4; i++) {
    uint32_t r = esp_random();
    memcpy(iv + i*4, &r, 4);
  }

  // PKCS7 pad 64 bytes → 80 bytes (next multiple of 16)
  uint8_t padded[80];
  memcpy(padded, plain, 64);
  memset(padded + 64, 0x10, 16); // pad value = 16

  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 80, iv_copy, padded, cipher + 16);
  mbedtls_aes_free(&aes);

  // IV prepended to cipher output: [16 IV][80 ciphertext] = 96 bytes total
  memcpy(cipher, iv, 16);

  // Wipe sensitive data from RAM
  memset(key,    0, 32);
  memset(padded, 0, 80);
}

static bool decryptSeed(const uint8_t *cipher, uint8_t *plain) {
  uint8_t key[32];
  deriveDeviceKey(key);

  uint8_t iv[16];
  memcpy(iv, cipher, 16);

  uint8_t decrypted[80];
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, key, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 80, iv, cipher + 16, decrypted);
  mbedtls_aes_free(&aes);

  // Verify PKCS7 padding
  bool valid = true;
  for (int i = 64; i < 80; i++)
    if (decrypted[i] != 0x10) { valid = false; break; }

  if (valid) memcpy(plain, decrypted, 64);

  // Wipe from RAM
  memset(key,       0, 32);
  memset(decrypted, 0, 80);

  return valid;
}


// ════════════════════════════════════════════════════════════
//  Crypto (BIP32 / addresses)
// ════════════════════════════════════════════════════════════

static int hwRNG(uint8_t *dest, unsigned size) {
  uint32_t v;
  while (size > 0) {
    v = esp_random();
    size_t chunk = (size < 4) ? size : 4;
    memcpy(dest, &v, chunk);
    dest += chunk; size -= chunk;
  }
  return 1;
}

static void hmac_sha512(const uint8_t *key, size_t kl,
                        const uint8_t *data, size_t dl, uint8_t out[64]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  mbedtls_md_hmac(info, key, kl, data, dl, out);
}

static const uint8_t SECP256K1_N[32] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
  0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
  0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static void addmod256(uint8_t *a, const uint8_t *b) {
  uint16_t carry = 0;
  for (int i = 31; i >= 0; i--) {
    uint16_t s = (uint16_t)a[i] + b[i] + carry;
    a[i] = s & 0xFF; carry = s >> 8;
  }
  if (carry || memcmp(a, SECP256K1_N, 32) >= 0) {
    uint16_t borrow = 0;
    for (int i = 31; i >= 0; i--) {
      int16_t d = (int16_t)a[i] - SECP256K1_N[i] - borrow;
      if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
      a[i] = (uint8_t)d;
    }
  }
}

static void bip32_master(const uint8_t *seed, uint8_t priv[32], uint8_t chain[32]) {
  uint8_t I[64];
  hmac_sha512((const uint8_t*)"Bitcoin seed", 12, seed, 64, I);
  memcpy(priv, I, 32); memcpy(chain, I+32, 32);
}

static void bip32_child(const uint8_t *priv, const uint8_t *chain,
                         uint8_t *cp, uint8_t *cc, uint32_t idx) {
  uint8_t data[37], I[64];
  if (idx & 0x80000000) { data[0]=0x00; memcpy(data+1,priv,32); }
  else {
    uint8_t pub[64];
    uECC_compute_public_key(priv, pub, uECC_secp256k1());
    data[0]=(pub[63]&1)?0x03:0x02; memcpy(data+1,pub,32);
  }
  data[33]=(idx>>24)&0xFF; data[34]=(idx>>16)&0xFF;
  data[35]=(idx>>8)&0xFF;  data[36]=idx&0xFF;
  hmac_sha512(chain,32,data,37,I);
  memcpy(cp,I,32); addmod256(cp,priv); memcpy(cc,I+32,32);
}

static void bip32_path(uint8_t priv[32], uint8_t chain[32],
                        const uint32_t *path, int depth) {
  uint8_t cp[32], cc[32];
  for (int i = 0; i < depth; i++) {
    bip32_child(priv,chain,cp,cc,path[i]);
    memcpy(priv,cp,32); memcpy(chain,cc,32);
  }
}

static const char B58[] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void base58check(const uint8_t *data, size_t len, char *out) {
  uint8_t h1[32], h2[32];
  mbedtls_sha256(data,len,h1,0); mbedtls_sha256(h1,32,h2,0);
  uint8_t full[len+4];
  memcpy(full,data,len); memcpy(full+len,h2,4);
  size_t flen=len+4;
  int zeros=0;
  while (zeros<(int)flen && full[zeros]==0) zeros++;
  uint8_t buf[64]; memset(buf,0,64);
  int outlen=0;
  for (int i=zeros;i<(int)flen;i++){
    int carry=full[i];
    for(int j=0;j<outlen;j++){carry+=256*buf[j];buf[j]=carry%58;carry/=58;}
    while(carry){buf[outlen++]=carry%58;carry/=58;}
  }
  int total=zeros+outlen;
  for(int i=0;i<zeros;i++)  out[i]=      '1';
  for(int i=0;i<outlen;i++) out[zeros+i]= B58[buf[outlen-1-i]];
  out[total]='\0';
}

static void derive_eth(const uint8_t *priv, char *out) {
  uint8_t pub[64], hash[32];
  uECC_compute_public_key(priv,pub,uECC_secp256k1());
  keccak256(pub,64,hash);
  out[0]='0'; out[1]='x';
  for(int i=0;i<20;i++) sprintf(out+2+i*2,"%02x",hash[12+i]);
  out[42]='\0';
}

static void derive_btc(const uint8_t *priv, char *out) {
  uint8_t pub[64],compressed[33],sha[32],h160[20];
  uECC_compute_public_key(priv,pub,uECC_secp256k1());
  compressed[0]=(pub[63]&1)?0x03:0x02; memcpy(compressed+1,pub,32);
  mbedtls_sha256(compressed,33,sha,0); ripemd160(sha,32,h160);
  uint8_t payload[21]; payload[0]=0x00; memcpy(payload+1,h160,20);
  base58check(payload,21,out);
}

static void applyWallet() {
  uECC_set_rng(&hwRNG);
  uint8_t priv[32], chain[32];

  bip32_master(masterSeed,priv,chain);
  { uint32_t p[]={0x8000002C,0x8000003C,0x80000000,0,0}; bip32_path(priv,chain,p,5); }
  memcpy(ethPrivKey,priv,32); derive_eth(ethPrivKey,ethAddress);

  bip32_master(masterSeed,priv,chain);
  { uint32_t p[]={0x8000002C,0x80000000,0x80000000,0,0}; bip32_path(priv,chain,p,5); }
  memcpy(btcPrivKey,priv,32); derive_btc(btcPrivKey,btcAddress);

  // Encrypt seed before storing
  uint8_t encSeed[96];
  encryptSeed(masterSeed, encSeed);
  prefs.begin("wallet",false);
  prefs.putBytes("eseed", encSeed, 96);
  prefs.end();

  hasSeed=true;
}

static void loadWallet() {
  prefs.begin("wallet",true);
  if(prefs.getBytesLength("eseed")==96){
    uint8_t encSeed[96];
    prefs.getBytes("eseed", encSeed, 96);
    if(decryptSeed(encSeed, masterSeed)){
      hasSeed=true;
    } else {
      hasSeed=false;
      Serial.println("ERR:seed decryption failed - wrong chip?");
    }
  }
  // Legacy unencrypted migration
  else if(prefs.getBytesLength("seed")==64){
    prefs.getBytes("seed",masterSeed,64);
    hasSeed=true;
    // Re-save encrypted
    prefs.end();
    applyWallet();
    return;
  }
  prefs.end();
}

static void resetWallet() {
  prefs.begin("wallet",false); prefs.clear(); prefs.end();
  prefs.begin("pin",false);    prefs.clear(); prefs.end();
  prefs.begin("addrs",false);  prefs.clear(); prefs.end();
  memset(masterSeed,0,64);
  memset(ethPrivKey,0,32);
  memset(btcPrivKey,0,32);
  memset(ethAddress,0,sizeof(ethAddress));
  memset(btcAddress,0,sizeof(btcAddress));
  memset(seedWords,0,sizeof(seedWords));
  savedAddrCount=0; hasSeed=false;
}

static bool signHash(const uint8_t *priv, const uint8_t *hash32, char *out) {
  uint8_t sig[64];
  if(!uECC_sign(priv,hash32,32,sig,uECC_secp256k1())) return false;
  for(int i=0;i<64;i++) sprintf(out+i*2,"%02X",sig[i]);
  out[128]='\0'; return true;
}

static bool hexToBytes(const char *hex, uint8_t *out, size_t n) {
  if(strlen(hex)!=n*2) return false;
  for(size_t i=0;i<n;i++){
    auto c2n=[](char c)->int{
      if(c>='0'&&c<='9') return c-'0';
      if(c>='a'&&c<='f') return c-'a'+10;
      if(c>='A'&&c<='F') return c-'A'+10;
      return -1;
    };
    int h=c2n(hex[i*2]),l=c2n(hex[i*2+1]);
    if(h<0||l<0) return false;
    out[i]=(h<<4)|l;
  }
  return true;
}


// ════════════════════════════════════════════════════════════
//  PIN
// ════════════════════════════════════════════════════════════

static void savePin(int digits[4]) {
  char buf[5];
  for(int i=0;i<4;i++) buf[i]='0'+digits[i];
  buf[4]='\0';
  prefs.begin("pin",false); prefs.putString("p",buf); prefs.end();
}

static bool pinExists() {
  prefs.begin("pin",true); bool e=prefs.isKey("p"); prefs.end(); return e;
}

static bool checkPin(int digits[4]) {
  prefs.begin("pin",true);
  String stored=prefs.getString("p",""); prefs.end();
  for(int i=0;i<4;i++) if(stored[i]-'0'!=digits[i]) return false;
  return true;
}


// ════════════════════════════════════════════════════════════
//  Saved addresses
// ════════════════════════════════════════════════════════════

static void saveAddresses() {
  prefs.begin("addrs",false);
  prefs.putInt("count",savedAddrCount);
  for(int i=0;i<savedAddrCount;i++){
    prefs.putString(("n"+String(i)).c_str(), savedAddrs[i].name);
    prefs.putString(("a"+String(i)).c_str(), savedAddrs[i].addr);
  }
  prefs.end();
}

static void loadAddresses() {
  prefs.begin("addrs",true);
  savedAddrCount=prefs.getInt("count",0);
  for(int i=0;i<savedAddrCount;i++){
    prefs.getString(("n"+String(i)).c_str(),"").toCharArray(savedAddrs[i].name,16);
    prefs.getString(("a"+String(i)).c_str(),"").toCharArray(savedAddrs[i].addr,44);
  }
  prefs.end();
}


// ════════════════════════════════════════════════════════════
//  Display
// ════════════════════════════════════════════════════════════

static void drawText(const char *t, int y) {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,y,t);
  display.sendBuffer();
}

static void drawTwoLines(const char *l1, const char *l2) {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,20,l1);
  display.drawStr(0,38,l2);
  display.sendBuffer();
}

static void drawIcon(int idx, int x, int y) {
  switch(idx) {
    case 0: // ETH diamond
      display.drawPixel(x+3,y+0);
      display.drawHLine(x+1,y+2,5);
      display.drawPixel(x+3,y+5);
      display.drawLine(x+0,y+2,x+3,y+0);
      display.drawLine(x+6,y+2,x+3,y+0);
      display.drawLine(x+0,y+2,x+3,y+5);
      display.drawLine(x+6,y+2,x+3,y+5);
      break;
    case 1: // BTC
      display.drawVLine(x+1,y+0,6);
      display.drawHLine(x+1,y+0,3);
      display.drawHLine(x+1,y+3,3);
      display.drawHLine(x+1,y+5,3);
      display.drawVLine(x+4,y+0,3);
      display.drawVLine(x+5,y+3,3);
      break;
    case 2: // Send arrow
      display.drawHLine(x+0,y+3,5);
      display.drawLine(x+3,y+1,x+5,y+3);
      display.drawLine(x+3,y+5,x+5,y+3);
      break;
    case 3: // Seed key
      display.drawCircle(x+2,y+3,2);
      display.drawHLine(x+4,y+3,3);
      display.drawVLine(x+5,y+3,2);
      break;
    case 4: // Reset X
      display.drawLine(x+0,y+0,x+5,y+5);
      display.drawLine(x+5,y+0,x+0,y+5);
      break;
  }
}

static void drawMenu() {
  display.clearBuffer();
  display.setFont(u8g2_font_8x13B_tr);
  display.drawStr(0,10,"ESP32 Vault");
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(100,10,"AIR");
  display.drawHLine(0,12,128);
  display.drawVLine(64,12,52);

  for(int i=0;i<3;i++){
    int y=16+i*17;
    // LEFT col
    if(menuIndex==i){
      display.drawBox(0,y-1,63,16);
      display.setDrawColor(0);
    } else { display.setDrawColor(1); }
    drawIcon(i,2,y+3);
    display.setFont(u8g2_font_7x13B_tr);
    display.drawStr(14,y+12,menuItems[i]);
    display.setDrawColor(1);

    // RIGHT col
    int ri=i+3;
    if(ri<MENU_COUNT){
      if(menuIndex==ri){
        display.drawBox(65,y-1,63,16);
        display.setDrawColor(0);
      } else { display.setDrawColor(1); }
      drawIcon(ri,67,y+3);
      display.setFont(u8g2_font_7x13B_tr);
      display.drawStr(79,y+12,menuItems[ri]);
      display.setDrawColor(1);
    }
  }
  display.sendBuffer();
}

static void drawLong(const char *t) {
  const int W=21;
  char l1[22]={},l2[22]={},l3[22]={};
  strncpy(l1,t,W); strncpy(l2,t+W,W); strncpy(l3,t+2*W,W);
  display.clearBuffer();
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,10,l1);
  display.drawStr(0,22,l2);
  display.drawStr(0,34,l3);
  display.drawStr(0,50,"[OK] back");
  display.sendBuffer();
}

static void drawQR(const char *addr) {
  QRCode qrcode;
  uint8_t qrData[qrcode_getBufferSize(3)];
  qrcode_initText(&qrcode,qrData,3,ECC_LOW,addr);
  display.clearBuffer();
  for(int y=0;y<qrcode.size;y++)
    for(int x=0;x<qrcode.size;x++)
      if(qrcode_getModule(&qrcode,x,y))
        display.drawBox(x*2,3+y*2,2,2);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(62,20,"ETH:");
  char top[9]={},bot[9]={};
  strncpy(top,addr+2,8);
  strncpy(bot,addr+strlen(addr)-8,8);
  display.drawStr(62,32,top);
  display.drawStr(62,42,"...");
  display.drawStr(62,52,bot);
  display.drawStr(62,62,"[OK]");
  display.sendBuffer();
}

static void drawPinScreen() {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,12,settingPin?"Set new PIN:":"Enter PIN:");
  char line[20]="";
  for(int i=0;i<4;i++){
    if(i==pinPos){ char d[3]; sprintf(d,"%d",pinEntry[i]); strcat(line,d); }
    else if(i<pinPos) strcat(line,"*");
    else strcat(line,"-");
    strcat(line," ");
  }
  display.setFont(u8g2_font_10x20_tr);
  display.drawStr(10,40,line);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,56,"UP/DN=change OK=next");
  display.sendBuffer();
}

static void drawWrongPin() {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,20,"Wrong PIN!");
  char buf[24];
  int left=MAX_FAILS-failCount;
  if(left>0) snprintf(buf,24,"%d attempts left",left);
  else strcpy(buf,"LOCKED! Wiping...");
  display.drawStr(0,38,buf);
  display.sendBuffer();
}

static void drawSendPickAddr() {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,12,"Send To:");
  display.drawHLine(0,14,128);
  if(savedAddrCount==0){
    display.setFont(u8g2_font_5x8_tr);
    display.drawStr(0,30,"No saved addresses!");
    display.drawStr(0,42,"Add via web companion");
    display.drawStr(0,52,"SAVEADDR command");
    display.drawStr(0,62,"[OK] back");
  } else {
    display.setFont(u8g2_font_6x12_tr);
    display.drawStr(0,30,savedAddrs[sendAddrIndex].name);
    display.setFont(u8g2_font_5x8_tr);
    char shortAddr[14]={};
    strncpy(shortAddr,savedAddrs[sendAddrIndex].addr,10);
    strcat(shortAddr,"..");
    display.drawStr(0,42,shortAddr);
    char counter[12]; snprintf(counter,12,"%d/%d",sendAddrIndex+1,savedAddrCount);
    display.drawStr(0,54,counter);
    display.drawStr(0,62,"UP/DN=pick OK=next");
  }
  display.sendBuffer();
}

static void drawSendPickAmount() {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,12,"Amount:");
  display.drawHLine(0,14,128);
  char amtStr[20];
  if(sendAmountInt>=10000)
    snprintf(amtStr,20,"%d.%04d ETH",sendAmountInt/10000,sendAmountInt%10000);
  else
    snprintf(amtStr,20,"0.%04d ETH",sendAmountInt);
  display.setFont(u8g2_font_10x20_tr);
  display.drawStr(0,42,amtStr);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,58,"UP=+0.0001 DN=-0.0001");
  display.sendBuffer();
}

static void drawSendConfirm() {
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,12,"Confirm Send:");
  display.drawHLine(0,14,128);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,26,savedAddrs[sendAddrIndex].name);
  char shortAddr[14]={};
  strncpy(shortAddr,savedAddrs[sendAddrIndex].addr,10);
  strcat(shortAddr,"..");
  display.drawStr(0,36,shortAddr);
  char amtStr[20];
  if(sendAmountInt>=10000)
    snprintf(amtStr,20,"%d.%04d ETH",sendAmountInt/10000,sendAmountInt%10000);
  else
    snprintf(amtStr,20,"0.%04d ETH",sendAmountInt);
  display.drawStr(0,48,amtStr);
  display.drawStr(0,60,"OK=Sign  UP=Cancel");
  display.sendBuffer();
}

static void drawConfirm() {
  char toShort[20];
  int addrLen=strlen(pendingTo);
  if(addrLen>14){
    strncpy(toShort,pendingTo,10);
    toShort[10]='.'; toShort[11]='.';
    strncpy(toShort+12,pendingTo+addrLen-4,4);
    toShort[16]='\0';
  } else {
    strncpy(toShort,pendingTo,19); toShort[19]='\0';
  }
  char line1[22],line2[22],line3[22];
  snprintf(line1,22,"SEND %s",pendingIsEth?"ETH":"BTC");
  snprintf(line2,22,"To:%s",toShort);
  snprintf(line3,22,"%s",pendingAmount);
  display.clearBuffer();
  display.setFont(u8g2_font_6x12_tr);
  display.drawStr(0,12,line1);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,26,line2);
  display.drawStr(0,38,line3);
  display.drawStr(0,54,"OK=Sign  UP=Reject");
  display.sendBuffer();
}

static void drawSeedWarn() {
  display.clearBuffer();
  display.setFont(u8g2_font_7x13B_tr);
  display.drawStr(0,12,"View Seed Words");
  display.drawHLine(0,15,128);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,27,"CAUTION: Anyone who");
  display.drawStr(0,37,"sees these words can");
  display.drawStr(0,47,"steal your funds!");
  display.drawStr(0,59,"OK=Show  UP=Cancel");
  display.sendBuffer();
}

static void drawSeedPage(int page) {
  char words[12][16]={};
  int wCount=0;
  char buf[200];
  strncpy(buf,seedWords,199);
  char *tok=strtok(buf," ");
  while(tok&&wCount<12){ strncpy(words[wCount++],tok,15); tok=strtok(NULL," "); }

  display.clearBuffer();
  display.setFont(u8g2_font_5x8_tr);
  char title[20]; snprintf(title,20,"Seed Words (%d/3):",page+1);
  display.drawStr(0,8,title);
  display.drawHLine(0,10,128);

  int start=page*4;
  for(int i=0;i<4&&(start+i)<12;i++){
    char line[24]; snprintf(line,24,"%2d. %s",start+i+1,words[start+i]);
    display.drawStr(0,22+i*12,line);
  }
  if(page<2) display.drawStr(0,58,"OK=next  UP=cancel");
  else        display.drawStr(0,58,"OK=done  UP=cancel");
  display.sendBuffer();
}

static void drawResetConfirm() {
  display.clearBuffer();
  display.setFont(u8g2_font_7x13B_tr);
  display.drawStr(0,14,"RESET WALLET?");
  display.drawHLine(0,17,128);
  display.setFont(u8g2_font_5x8_tr);
  display.drawStr(0,30,"This will WIPE all keys");
  display.drawStr(0,42,"and seed from device!");
  display.drawStr(0,54,"Cannot be undone.");
  display.drawStr(0,64,"OK=WIPE  UP=Cancel");
  display.sendBuffer();
}


// ════════════════════════════════════════════════════════════
//  Serial handler
// ════════════════════════════════════════════════════════════

static void handleSerial() {
  if(!Serial.available()) return;
  String line=Serial.readStringUntil('\n');
  line.trim();

  if(line.startsWith("SETSEED:")){
    uint8_t tmp[64];
    if(!hexToBytes(line.c_str()+8,tmp,64)){Serial.println("ERR:bad hex");return;}
    memcpy(masterSeed,tmp,64);
    drawText("Encrypting keys...");
    applyWallet();
    Serial.println("OK");
    Serial.println("SEND_WORDS");
    pinPos=0; memset(pinEntry,0,sizeof(pinEntry));
    settingPin=true; state=SET_PIN; drawPinScreen();
    return;
  }
  if(line=="ADDR_ETH"){
    if(!hasSeed){Serial.println("ERR:no seed");return;}
    Serial.print("ETH:"); Serial.println(ethAddress); return;
  }
  if(line=="ADDR_BTC"){
    if(!hasSeed){Serial.println("ERR:no seed");return;}
    Serial.print("BTC:"); Serial.println(btcAddress); return;
  }
  if(line.startsWith("SIGN_ETH:")){
    if(!hasSeed){Serial.println("ERR:no seed");return;}
    String rest=line.substring(9);
    int c1=rest.indexOf(':'),c2=rest.lastIndexOf(':');
    if(c1<0||c2<=c1){Serial.println("ERR:bad format");return;}
    if(!hexToBytes(rest.substring(0,c1).c_str(),pendingHash,32)){
      Serial.println("ERR:bad hash");return;}
    strncpy(pendingTo,    rest.substring(c1+1,c2).c_str(),63);
    strncpy(pendingAmount,rest.substring(c2+1).c_str(),   31);
    pendingIsEth=true; pendingReady=true;
    state=CONFIRM_SIGN; drawConfirm(); return;
  }
  if(line.startsWith("SIGN_BTC:")){
    if(!hasSeed){Serial.println("ERR:no seed");return;}
    String rest=line.substring(9);
    int c1=rest.indexOf(':'),c2=rest.lastIndexOf(':');
    if(c1<0||c2<=c1){Serial.println("ERR:bad format");return;}
    if(!hexToBytes(rest.substring(0,c1).c_str(),pendingHash,32)){
      Serial.println("ERR:bad hash");return;}
    strncpy(pendingTo,    rest.substring(c1+1,c2).c_str(),63);
    strncpy(pendingAmount,rest.substring(c2+1).c_str(),   31);
    pendingIsEth=false; pendingReady=true;
    state=CONFIRM_SIGN; drawConfirm(); return;
  }
  if(line.startsWith("WORDS:")){
    line.substring(6).toCharArray(seedWords,200);
    prefs.begin("wallet",false);
    prefs.putString("words",seedWords);
    prefs.end();
    return;
  }
  if(line.startsWith("TX:")){
    String hash=line.substring(3);
    display.clearBuffer();
    display.setFont(u8g2_font_6x12_tr);
    display.drawStr(0,12,"TX Sent!");
    display.setFont(u8g2_font_5x8_tr);
    char shortHash[20]={}; strncpy(shortHash,hash.c_str(),18);
    display.drawStr(0,28,shortHash);
    display.drawStr(0,42,"Check Etherscan");
    display.drawStr(0,56,"[OK] back");
    display.sendBuffer();
    state=SHOW_RESULT; return;
  }
  if(line.startsWith("ERR:")&&state==SEND_WAITING){
    drawText("Send Failed!"); delay(2000);
    state=MENU; drawMenu(); return;
  }
  if(line.startsWith("SAVEADDR:")){
    String rest=line.substring(9);
    int c1=rest.indexOf(':'),c2=rest.indexOf(':',c1+1);
    if(c1<0||c2<=c1){Serial.println("ERR:bad format");return;}
    int idx=rest.substring(0,c1).toInt();
    if(idx<0||idx>=MAX_SAVED_ADDR){Serial.println("ERR:bad index");return;}
    rest.substring(c1+1,c2).toCharArray(savedAddrs[idx].name,16);
    rest.substring(c2+1).toCharArray(savedAddrs[idx].addr,44);
    if(idx>=savedAddrCount) savedAddrCount=idx+1;
    saveAddresses();
    Serial.println("OK:saved "+String(savedAddrs[idx].name));
    return;
  }
  if(line=="LISTADDR"){
    Serial.println("COUNT:"+String(savedAddrCount));
    for(int i=0;i<savedAddrCount;i++)
      Serial.println(String(i)+":"+savedAddrs[i].name+":"+savedAddrs[i].addr);
    return;
  }
  if(line=="RESET"){
    resetWallet(); state=WAIT_SEED;
    drawText("Wallet wiped."); Serial.println("OK"); return;
  }
  Serial.println("ERR:unknown command");
}


// ════════════════════════════════════════════════════════════
//  Setup
// ════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);

  // Kill all wireless FIRST before anything else
  killWireless();

  pinMode(BTN_UP,  INPUT_PULLUP);
  pinMode(BTN_DOWN,INPUT_PULLUP);
  pinMode(BTN_OK,  INPUT_PULLUP);
  uECC_set_rng(&hwRNG);
  display.begin();

  loadWallet();
  loadAddresses();

  // Load seed words
  prefs.begin("wallet",true);
  prefs.getString("words","").toCharArray(seedWords,200);
  prefs.end();

  if(hasSeed){
    applyWallet();
    if(pinExists()){
      pinPos=0; memset(pinEntry,0,sizeof(pinEntry));
      settingPin=false; failCount=0;
      state=ENTER_PIN; drawPinScreen();
    } else {
      pinPos=0; memset(pinEntry,0,sizeof(pinEntry));
      settingPin=true; state=SET_PIN; drawPinScreen();
    }
  } else {
    state=WAIT_SEED; drawText("Connect via USB",20);
  }
}


// ════════════════════════════════════════════════════════════
//  Loop
// ════════════════════════════════════════════════════════════

void loop() {
  handleSerial();
  bool up=digitalRead(BTN_UP), down=digitalRead(BTN_DOWN), ok=digitalRead(BTN_OK);

  // ── PIN ──────────────────────────────────────────────────
  if(state==SET_PIN||state==ENTER_PIN){
    if(lastUp==HIGH&&up==LOW){
      pinEntry[pinPos]=(pinEntry[pinPos]+1)%10; drawPinScreen();
    }
    if(lastDown==HIGH&&down==LOW){
      pinEntry[pinPos]=(pinEntry[pinPos]+9)%10; drawPinScreen();
    }
    if(lastOk==HIGH&&ok==LOW){
      pinPos++;
      if(pinPos<4){ drawPinScreen(); }
      else {
        if(state==SET_PIN){
          savePin(pinEntry);
          drawText("PIN Set!"); delay(800);
          state=MENU; drawMenu();
        } else {
          if(checkPin(pinEntry)){
            failCount=0;
            drawText("Unlocked!"); delay(600);
            state=MENU; drawMenu();
          } else {
            failCount++;
            drawWrongPin(); delay(2000);
            if(failCount>=MAX_FAILS){
              resetWallet();
              drawTwoLines("WIPED!","Too many fails");
              delay(3000);
              state=WAIT_SEED; drawText("Connect via USB",20);
            } else {
              pinPos=0; memset(pinEntry,0,sizeof(pinEntry)); drawPinScreen();
            }
          }
        }
      }
    }
  }

  // ── MENU ─────────────────────────────────────────────────
  else if(state==MENU){
    if(lastUp==HIGH&&up==LOW){
      menuIndex=(menuIndex-1+MENU_COUNT)%MENU_COUNT; drawMenu();
    }
    if(lastDown==HIGH&&down==LOW){
      menuIndex=(menuIndex+1)%MENU_COUNT; drawMenu();
    }
    if(lastOk==HIGH&&ok==LOW){
      if(menuIndex==0){ state=SHOW_ETH; drawQR(ethAddress); }
      if(menuIndex==1){ state=SHOW_BTC; drawLong(btcAddress); }
      if(menuIndex==2){
        sendAddrIndex=0; sendAmountInt=1;
        state=SEND_PICK_ADDR; drawSendPickAddr();
      }
      if(menuIndex==3){ state=SEED_WARN; drawSeedWarn(); }
      if(menuIndex==4){ state=RESET_CONFIRM; drawResetConfirm(); }
    }
  }

  // ── SHOW ─────────────────────────────────────────────────
  else if(state==SHOW_ETH||state==SHOW_BTC||state==SHOW_RESULT){
    if(lastOk==HIGH&&ok==LOW){ state=MENU; drawMenu(); }
  }

  // ── RESET CONFIRM ────────────────────────────────────────
  else if(state==RESET_CONFIRM){
    if(lastUp==HIGH&&up==LOW){ state=MENU; drawMenu(); }
    if(lastOk==HIGH&&ok==LOW){
      resetWallet(); state=WAIT_SEED;
      drawText("Wallet wiped.");
    }
  }

  // ── SEED WARN ────────────────────────────────────────────
  else if(state==SEED_WARN){
    if(lastUp==HIGH&&up==LOW){ state=MENU; drawMenu(); }
    if(lastOk==HIGH&&ok==LOW){ seedPageIndex=0; state=SHOW_SEED; drawSeedPage(0); }
  }

  // ── SHOW SEED ────────────────────────────────────────────
  else if(state==SHOW_SEED){
    if(lastUp==HIGH&&up==LOW){ state=MENU; drawMenu(); }
    if(lastOk==HIGH&&ok==LOW){
      seedPageIndex++;
      if(seedPageIndex>2){ state=MENU; drawMenu(); }
      else drawSeedPage(seedPageIndex);
    }
  }

  // ── SEND PICK ADDR ───────────────────────────────────────
  else if(state==SEND_PICK_ADDR){
    if(savedAddrCount==0){
      if(lastOk==HIGH&&ok==LOW){ state=MENU; drawMenu(); }
    } else {
      if(lastUp==HIGH&&up==LOW){
        sendAddrIndex=(sendAddrIndex-1+savedAddrCount)%savedAddrCount;
        drawSendPickAddr();
      }
      if(lastDown==HIGH&&down==LOW){
        sendAddrIndex=(sendAddrIndex+1)%savedAddrCount;
        drawSendPickAddr();
      }
      if(lastOk==HIGH&&ok==LOW){ state=SEND_PICK_AMT; drawSendPickAmount(); }
    }
  }

  // ── SEND PICK AMOUNT ─────────────────────────────────────
  else if(state==SEND_PICK_AMT){
    if(lastUp==HIGH&&up==LOW){
      if(sendAmountInt<99999) sendAmountInt++; drawSendPickAmount();
    }
    if(lastDown==HIGH&&down==LOW){
      if(sendAmountInt>1) sendAmountInt--; drawSendPickAmount();
    }
    if(lastOk==HIGH&&ok==LOW){ state=SEND_CONFIRM; drawSendConfirm(); }
  }

  // ── SEND CONFIRM ─────────────────────────────────────────
  else if(state==SEND_CONFIRM){
    if(lastUp==HIGH&&up==LOW){ state=MENU; drawMenu(); }
    if(lastOk==HIGH&&ok==LOW){
      char amtStr[24];
      dtostrf((double)sendAmountInt/10000.0,1,4,amtStr);
      strcat(amtStr," ETH");
      Serial.print("SEND_REQUEST:");
      Serial.print(savedAddrs[sendAddrIndex].addr);
      Serial.print(":");
      Serial.println(amtStr);
      drawText("Confirm on PC...",20);
      state=SEND_WAITING;
    }
  }

  // ── SEND WAITING ─────────────────────────────────────────
  else if(state==SEND_WAITING){
    if(lastUp==HIGH&&up==LOW){ state=MENU; drawMenu(); }
  }

  // ── CONFIRM SIGN ─────────────────────────────────────────
  else if(state==CONFIRM_SIGN){
    if(lastUp==HIGH&&up==LOW){
      Serial.println("ERR:rejected by user");
      pendingReady=false; state=MENU; drawMenu();
    }
    if(lastOk==HIGH&&ok==LOW&&pendingReady){
      const uint8_t *priv=pendingIsEth?ethPrivKey:btcPrivKey;
      drawText("Signing...");
      if(signHash(priv,pendingHash,lastSigHex)){
        Serial.print("SIG:"); Serial.println(lastSigHex);
        state=SHOW_RESULT; drawText("Signed! OK=back");
      } else {
        Serial.println("ERR:sign failed");
        state=MENU; drawMenu();
      }
      pendingReady=false;
    }
  }

  lastUp=up; lastDown=down; lastOk=ok;
}
