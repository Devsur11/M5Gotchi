// Full crypto implementation for ESP32 (Arduino) using mbedTLS + SD
// - RSA-OAEP for key encapsulation
// - AES-256-GCM for payload
// - RSA-PSS (mbedTLS pk_sign/verify) with SHA256
//
// WARNING:
// - RSA 4096 is heavy. Key generation may take a long time and may fail if
//   mbedTLS was built with too-small MPI limits. If failing, generate keys on PC
//   and copy to SD card under keysPath (/sd/keys/id_rsa and id_rsa.pub).
// - Ensure SD.begin() has been called before using ensureKeys/load*.
//

#include "crypto.h"
#include <SD.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include <vector>
#include <cstring>
#include "settings.h"
#include "esp_heap_caps.h"
#include "esp_system.h"

using namespace pwngrid::crypto;

static String g_keysPath = "/pwngrid/keys";
static const int RSA_BITS = 2048;
static const size_t AES_KEY_LEN = 16;
static const size_t GCM_NONCE_LEN = 12;
static const size_t GCM_TAG_LEN = 16;
static const size_t PRIV_PEM_BUF = 16000; // adjust up if you use 4096-bit keys
static const size_t PUB_PEM_BUF  = 4096;


static String fullPrivatePath() { return g_keysPath + "/id_rsa"; }
static String fullPublicPath()  { return g_keysPath + "/id_rsa.pub"; }
static String tokenPath()       { return g_keysPath + "/../token.json"; } // convenience
static SemaphoreHandle_t keygenDone = nullptr;
// forward declarations for SD helpers defined later in this file
static bool writeFileSD(const String &path, const uint8_t *data, size_t len);
static bool readFileSD(const String &path, std::vector<uint8_t> &out);

// Ensure pub PEM uses "RSA PUBLIC KEY" header and exactly one trailing newline


void keygenTask(void *arg) {
    String privPath = fullPrivatePath();
    String pubPath  = fullPublicPath();

    
    // show heap before anything heavy
    size_t free_before = esp_get_free_heap_size();
    fLogMessage("[crypto] free heap before keygen: %u\n", (unsigned)free_before);

    if (!SD.exists(privPath.c_str()) || !SD.exists(pubPath.c_str())) {
        logMessage("[crypto] keys not found on SD. Generating RSA keypair (this will take a while)...");

        // Declare all locals that could be bypassed by early jumps here to avoid
        // "transfer of control bypasses initialization" errors.
        mbedtls_pk_context pk;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr;
        void *prv_buf = nullptr;
        void *pub_buf = nullptr;
        size_t prv_len = 0;
        size_t pub_len = 0;
        String dir;
        // Strings that would otherwise be constructed later must be declared
        // here to avoid gotos bypassing their constructors.
        // String pubPemRaw;
        // String pubPemNorm;
        bool ok1 = false;
        bool ok2 = false;
        int rc = 0;

        mbedtls_pk_init(&pk);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr);

        const char *pers = "esp32_rsa_gen";
        rc = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
        if (rc != 0) {
            fLogMessage("[crypto] ctr_drbg_seed failed: -0x%04x\n", -rc);
            mbedtls_ctr_drbg_free(&ctr);
            mbedtls_entropy_free(&entropy);
        }

        if ((rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
            fLogMessage("[crypto] pk_setup failed: -0x%04x\n", -rc);
            mbedtls_ctr_drbg_free(&ctr);
            mbedtls_entropy_free(&entropy);
        }

        // Generate RSA key (may take a long time)
        fLogMessage("[crypto] starting RSA key generation, be patient (bits=%d)...\n", RSA_BITS);
        if ((rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr, RSA_BITS, 65537)) != 0) {
            fLogMessage("[crypto] rsa_gen_key failed: -0x%04x\n", -rc);
            mbedtls_pk_free(&pk);
        }

        // allocate PEM buffers in SPIRAM if available, otherwise in regular heap
        prv_buf = heap_caps_malloc(PRIV_PEM_BUF, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!prv_buf) {
            // fallback to normal heap
            prv_buf = heap_caps_malloc(PRIV_PEM_BUF, MALLOC_CAP_8BIT);
        }
        if (!prv_buf) {
            fLogMessage("[crypto] failed to alloc private pem buffer, free=%u\n", (unsigned)esp_get_free_heap_size());
            mbedtls_pk_free(&pk);
        }

        pub_buf = heap_caps_malloc(PUB_PEM_BUF, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!pub_buf) pub_buf = heap_caps_malloc(PUB_PEM_BUF, MALLOC_CAP_8BIT);
        if (!pub_buf) {
            fLogMessage("[crypto] failed to alloc public pem buffer, free=%u\n", (unsigned)esp_get_free_heap_size());
            heap_caps_free(prv_buf);
            mbedtls_pk_free(&pk);
        }

        // export private pem
        rc = mbedtls_pk_write_key_pem(&pk, (unsigned char*)prv_buf, PRIV_PEM_BUF);
        if (rc != 0) {
            fLogMessage("[crypto] write_key_pem failed: -0x%04x\n", -rc);
            heap_caps_free(prv_buf);
            heap_caps_free(pub_buf);
            mbedtls_pk_free(&pk);
        }
        prv_len = strlen((const char*)prv_buf);

        // export public pem
        rc = mbedtls_pk_write_pubkey_pem(&pk, (unsigned char*)pub_buf, PUB_PEM_BUF);
        if (rc != 0) {
            fLogMessage("[crypto] write_pubkey_pem failed: -0x%04x\n", -rc);
            heap_caps_free(prv_buf);
            heap_caps_free(pub_buf);
            mbedtls_pk_free(&pk);
        }
        pub_len = strlen((const char*)pub_buf);

        // ensure keys directory exists on SD
        dir = g_keysPath;
        if (!SD.exists(dir.c_str())) {
            SD.mkdir(dir.c_str());
        }

        ok1 = writeFileSD(privPath, (const uint8_t*)prv_buf, prv_len);
        // convert pub_buf (C string) to String and normalize header before saving
        String pubPemRaw((const char*)pub_buf, pub_len);
        String pubPemNorm = pwngrid::crypto::normalizePublicPEM(pubPemRaw);
        ok2 = writeFileSD(pubPath, (const uint8_t*)pubPemNorm.c_str(), pubPemNorm.length());

        heap_caps_free(prv_buf);
        heap_caps_free(pub_buf);

        if (!ok1 || !ok2) {
            fLogMessage("[crypto] failed to write key files to SD: ok1=%d ok2=%d\n", ok1, ok2);
            mbedtls_pk_free(&pk);
        }

        fLogMessage("[crypto] keygen saved private %s public %s\n", privPath.c_str(), pubPath.c_str());
    }

    // Done. Delete this task.
    xSemaphoreGive(keygenDone);
    vTaskDelete(NULL);
}

// ---------- SD helpers ----------
static bool writeFileSD(const String &path, const uint8_t *data, size_t len) {
    File f = SD.open(path.c_str(), FILE_WRITE);
    if (!f) {
        fLogMessage("[crypto] writeFileSD: open failed %s\n", path.c_str());
        return false;
    }
    size_t w = f.write(data, len);
    f.close();
    return w == len;
}
static bool readFileSD(const String &path, std::vector<uint8_t> &out) {
    if (!SD.exists(path.c_str())) return false;
    File f = SD.open(path.c_str(), FILE_READ);
    if (!f) return false;
    out.clear();
    while (f.available()) out.push_back((uint8_t)f.read());
    f.close();
    return true;
}

// ---------- base64 ----------
String pwngrid::crypto::base64Encode(const std::vector<uint8_t> &data) {
    size_t olen = 0;
    if (mbedtls_base64_encode(nullptr, 0, &olen, data.data(), data.size()) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && olen == 0) {
        // unexpected, but continue
    }
    std::vector<uint8_t> out(olen + 1);
    if (mbedtls_base64_encode(out.data(), out.size(), &olen, data.data(), data.size()) != 0) {
        return String();
    }
    out.resize(olen);
    return String((const char*)out.data(), out.size());
}

std::vector<uint8_t> pwngrid::crypto::base64Decode(const String &b64) {
    std::vector<uint8_t> out;
    const char* s = b64.c_str();
    size_t slen = b64.length();
    size_t olen = 0;
    // first pass to get required output length
    int ret = mbedtls_base64_decode(nullptr, 0, &olen, (const unsigned char*)s, slen);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && ret != MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        // proceed anyway
    }
    out.resize(olen + 1);
    if (mbedtls_base64_decode(out.data(), out.size(), &olen, (const unsigned char*)s, slen) != 0) {
        out.clear();
        return out;
    }
    out.resize(olen);
    return out;
}

// ---------- key generation / load ----------
bool pwngrid::crypto::ensureKeys(const String &keysPath) {
    keygenDone = xSemaphoreCreateBinary();
    xTaskCreatePinnedToCore(keygenTask, "keygen", 32768, NULL, 1, NULL, 0);
    while(xSemaphoreTake(keygenDone, 0) == pdFALSE){
        delay(10);
    }
    vSemaphoreDelete(keygenDone);
    return true;
    
}

bool pwngrid::crypto::loadPrivatePEM(String &out) {
    std::vector<uint8_t> v;
    if (!readFileSD(fullPrivatePath(), v)) return false;
    out = String((const char*)v.data(), v.size());
    return true;
}
bool pwngrid::crypto::loadPublicPEM(String &out) {
    std::vector<uint8_t> v;
    if (!readFileSD(fullPublicPath(), v)) return false;
    out = String((const char*)v.data(), v.size());
    return true;
}

String pwngrid::crypto::publicPEMBase64() {
    String pub;
    if (!loadPublicPEM(pub)) return String();
    String pubNorm = pwngrid::crypto::normalizePublicPEM(pub);
    std::vector<uint8_t> v((const uint8_t*)pubNorm.c_str(), (const uint8_t*)pubNorm.c_str() + pubNorm.length());
    return base64Encode(v);
}

bool pwngrid::crypto::verifyMessageWithPubPEM(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sig, const String &pubPEM) {
    if (pubPEM.length() == 0) return false;

    // Normalize header in memory: python client changes header to RSA PUBLIC KEY.
    String pubNorm = pubPEM;//pwngrid::crypto::normalizePublicPEM(pubPEM);

    std::vector<uint8_t> pub(pubNorm.length() + 1);
    memcpy(pub.data(), pubNorm.c_str(), pubNorm.length());
    pub[pubNorm.length()] = 0;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (mbedtls_pk_parse_public_key(&pk, pub.data(), pub.size()) != 0) {
        mbedtls_pk_free(&pk);
        logMessage("[crypto] verify: parse public key failed");
        return false;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        mbedtls_pk_free(&pk);
        logMessage("[crypto] verify: not RSA");
        return false;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    // compute SHA256 of message
    unsigned char hash[32];
    mbedtls_sha256(msg.data(), msg.size(), hash, 0);

    // set RSA padding to PSS + SHA256 and saltlen=16
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
#if defined(MBEDTLS_VERSION_NUMBER)
    rsa->salt_len = 16;
#endif

    // verify using rsa specific verify (preferred)
    int rc = mbedtls_rsa_rsassa_pss_verify(rsa, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, hash, sig.data());
    if (rc != 0) {
        // fallback to generic verify (mbedtls_pk_verify) which may use the rsa padding we set
        rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, sig.data(), sig.size());
        if (rc != 0) {
            fLogMessage("[crypto] verify failed: -0x%04x\n", -rc);
            mbedtls_pk_free(&pk);
            return false;
        }
    }

    mbedtls_pk_free(&pk);
    return true;
}

// ---------- signMessage (fixed hashlen and fallback usage) ----------
bool pwngrid::crypto::signMessage(const std::vector<uint8_t> &msg, std::vector<uint8_t> &outSig) {
    std::vector<uint8_t> priv;
    if (!readFileSD(fullPrivatePath(), priv)) {
        logMessage("[crypto] signMessage: private key not found");
        return false;
    }
    // ensure null termination for mbedtls parsing
    if (priv.empty() || priv.back() != 0) priv.push_back(0);

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);

    const char *pers = "pwngrid_sign";
    int rc = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (rc != 0) {
        fLogMessage("[crypto] signMessage: ctr_drbg_seed failed: -0x%04x\n", -rc);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    rc = mbedtls_pk_parse_key(&pk, priv.data(), priv.size(), nullptr, 0);
    if (rc != 0) {
        fLogMessage("[crypto] signMessage: pk_parse_key failed: -0x%04x\n", -rc);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        logMessage("[crypto] signMessage: key not RSA");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // Get the specific RSA context from the generic PK context
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);

    // 1. Compute SHA256 of the message
    unsigned char hash[32];
    mbedtls_sha256(msg.data(), msg.size(), hash, 0); // 0 -> SHA256

    // 2. Set the PSS padding and MGF1 hash algorithm on the context.
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    // 3. Prepare the output buffer. The signature will be the full key length.
    size_t key_len = mbedtls_pk_get_len(&pk);
    outSig.assign(key_len, 0);

    // 4. Call the correct _ext function with the explicit salt length.
    rc = mbedtls_rsa_rsassa_pss_sign_ext(
        rsa,                       // The rsa context
        mbedtls_ctr_drbg_random,   // RNG function
        &ctr,                      // RNG context
        MBEDTLS_MD_SHA256,         // The hash algorithm *of the message*
        32,                        // The hash length (SHA256)
        hash,                      // The pre-computed hash
        16,                        // Explicit salt length
        outSig.data()              // The output signature buffer
    );

    if (rc != 0) {
        fLogMessage("[crypto] signMessage: mbedtls_rsa_rsassa_pss_sign_ext failed: -0x%04x\n", -rc);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }
    
    // Success. cleanup and return true.
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    return true;
}
// === Helper: try parse public key tolerant to "RSA PUBLIC KEY" vs "PUBLIC KEY" ===
static int parse_public_key_tolerant(mbedtls_pk_context *pk, const uint8_t *pem, size_t pem_len) {
    // try raw first
    int rc = mbedtls_pk_parse_public_key(pk, pem, pem_len);
    if (rc == 0) return 0;

    // try swapping headers if present: "RSA PUBLIC KEY" <-> "PUBLIC KEY"
    std::string s(reinterpret_cast<const char*>(pem), pem_len);
    if (s.find("-----BEGIN RSA PUBLIC KEY-----") != std::string::npos) {
        // convert to "PUBLIC KEY" (SubjectPublicKeyInfo) form that mbedtls sometimes expects
        std::string s2 = s;
        size_t p1 = s2.find("-----BEGIN RSA PUBLIC KEY-----");
        if (p1 != std::string::npos) s2.replace(p1, strlen("-----BEGIN RSA PUBLIC KEY-----"), "-----BEGIN PUBLIC KEY-----");
        size_t p2 = s2.find("-----END RSA PUBLIC KEY-----");
        if (p2 != std::string::npos) s2.replace(p2, strlen("-----END RSA PUBLIC KEY-----"), "-----END PUBLIC KEY-----");
        rc = mbedtls_pk_parse_public_key(pk, (const unsigned char*)s2.c_str(), s2.size() + 1);
        if (rc == 0) return 0;
    } else if (s.find("-----BEGIN PUBLIC KEY-----") != std::string::npos) {
        // try converting to RSA PUBLIC KEY (less likely to help, but harmless)
        std::string s2 = s;
        size_t p1 = s2.find("-----BEGIN PUBLIC KEY-----");
        if (p1 != std::string::npos) s2.replace(p1, strlen("-----BEGIN PUBLIC KEY-----"), "-----BEGIN RSA PUBLIC KEY-----");
        size_t p2 = s2.find("-----END PUBLIC KEY-----");
        if (p2 != std::string::npos) s2.replace(p2, strlen("-----END PUBLIC KEY-----"), "-----END RSA PUBLIC KEY-----");
        rc = mbedtls_pk_parse_public_key(pk, (const unsigned char*)s2.c_str(), s2.size() + 1);
        if (rc == 0) return 0;
    }

    return rc;
}

// ---------- Encrypt (patched) ----------
bool pwngrid::crypto::encryptFor(const std::vector<uint8_t> &cleartext, const String &recipientPubPEM, std::vector<uint8_t> &out) {
    if (recipientPubPEM.length() == 0) {
        logMessage("[crypto] encryptFor: recipient public key empty");
        return false;
    }

    // Make a null-terminated copy
    std::vector<uint8_t> pubbuf(recipientPubPEM.length() + 1);
    memcpy(pubbuf.data(), recipientPubPEM.c_str(), recipientPubPEM.length());
    pubbuf[recipientPubPEM.length()] = 0;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    if (parse_public_key_tolerant(&pk, pubbuf.data(), pubbuf.size()) != 0) {
        logMessage("[crypto] encryptFor: parse public key failed");
        mbedtls_pk_free(&pk);
        return false;
    }

    // CTR DRBG for randomness
    mbedtls_ctr_drbg_context ctr;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr);
    mbedtls_entropy_init(&entropy);
    const char *pers = "enc_aes";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0) {
        logMessage("[crypto] ctr seed failed");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // generate random AES key (must match python's 16 bytes)
    std::vector<uint8_t> aesKey(AES_KEY_LEN);
    if (mbedtls_ctr_drbg_random(&ctr, aesKey.data(), AES_KEY_LEN) != 0) {
        logMessage("[crypto] ctr random aesKey failed");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // --- RSA-OAEP-SHA256 encrypt AES key explicitly ---
    // ensure pk is RSA
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        logMessage("[crypto] encryptFor: public key is not RSA");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    // set padding to RSAES-OAEP (PKCS1 v2) and hash to SHA256
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    // if () {
    //     logMessage("[crypto] encryptFor: failed to set rsa padding");
    //     mbedtls_pk_free(&pk);
    //     mbedtls_ctr_drbg_free(&ctr);
    //     mbedtls_entropy_free(&entropy);
    //     return false;
    // }

    size_t rsa_len = mbedtls_pk_get_len(&pk);
    std::vector<uint8_t> encKey(rsa_len);
    int rc = mbedtls_rsa_rsaes_oaep_encrypt(rsa,
            mbedtls_ctr_drbg_random, &ctr,
            MBEDTLS_RSA_PUBLIC,
            nullptr, 0, // label, label_len (python used None)
            AES_KEY_LEN, aesKey.data(), encKey.data());
    if (rc != 0) {
        fLogMessage("[crypto] oaep encrypt failed: -0x%04x\n", -rc);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }
    // encKey is rsa_len bytes (full modulus). If you need exact length, use rsa_len.

    // prepare nonce
    unsigned char nonce[GCM_NONCE_LEN];
    if (mbedtls_ctr_drbg_random(&ctr, nonce, GCM_NONCE_LEN) != 0) {
        logMessage("[crypto] ctr random nonce failed");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // GCM encrypt
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey.data(), AES_KEY_LEN * 8) != 0) {
        logMessage("[crypto] gcm_setkey failed");
        mbedtls_gcm_free(&gcm);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    size_t ct_len = cleartext.size();
    std::vector<uint8_t> ciphertext(ct_len);
    unsigned char tag[GCM_TAG_LEN];

    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, ct_len,
            nonce, GCM_NONCE_LEN,
            nullptr, 0,
            cleartext.data(), ciphertext.data(),
            GCM_TAG_LEN, tag);
    if (rc != 0) {
        fLogMessage("[crypto] gcm_crypt_and_tag failed: -0x%04x\n", -rc);
        mbedtls_gcm_free(&gcm);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // assemble output: nonce(12) + keySize(4 little endian) + encKey + ciphertext + tag(16)
    out.clear();
    out.insert(out.end(), nonce, nonce + GCM_NONCE_LEN);

    uint32_t ksz = (uint32_t)encKey.size();
    out.push_back((uint8_t)(ksz & 0xff));
    out.push_back((uint8_t)((ksz >> 8) & 0xff));
    out.push_back((uint8_t)((ksz >> 16) & 0xff));
    out.push_back((uint8_t)((ksz >> 24) & 0xff));

    out.insert(out.end(), encKey.begin(), encKey.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag, tag + GCM_TAG_LEN);

    // cleanup
    mbedtls_gcm_free(&gcm);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);

    return true;
}

// ---------- Decrypt (patched) ----------
bool pwngrid::crypto::decrypt(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &outCleartext) {
    // layout: nonce(12) + 4 bytes key size + encKey + ciphertext + tag(16)
    size_t minLen = GCM_NONCE_LEN + 4 + GCM_TAG_LEN;
    if (ciphertext.size() < minLen) {
        logMessage("[crypto] decrypt: buffer too small");
        return false;
    }
    size_t idx = 0;
    const uint8_t *buf = ciphertext.data();

    unsigned char nonce[GCM_NONCE_LEN];
    memcpy(nonce, buf + idx, GCM_NONCE_LEN); idx += GCM_NONCE_LEN;

    uint32_t ksz = (uint32_t)buf[idx] | ((uint32_t)buf[idx+1] << 8) | ((uint32_t)buf[idx+2] << 16) | ((uint32_t)buf[idx+3] << 24);
    idx += 4;

    if (ciphertext.size() < idx + ksz + GCM_TAG_LEN) {
        logMessage("[crypto] decrypt: invalid sizes");
        return false;
    }

    std::vector<uint8_t> encKey(buf + idx, buf + idx + ksz);
    idx += ksz;

    size_t ct_plus_tag = ciphertext.size() - idx;
    if (ct_plus_tag < GCM_TAG_LEN) {
        logMessage("[crypto] decrypt: missing tag");
        return false;
    }
    size_t ct_len = ct_plus_tag - GCM_TAG_LEN;
    const uint8_t *ct_ptr = buf + idx;
    const uint8_t *tag_ptr = buf + idx + ct_len;

    // load our private key from SD
    std::vector<uint8_t> priv;
    if (!readFileSD(fullPrivatePath(), priv)) {
        logMessage("[crypto] decrypt: private key missing");
        return false;
    }
    // ensure null termination
    if (priv.empty() || priv.back() != 0) priv.push_back(0);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;
    mbedtls_ctr_drbg_init(&ctr);
    mbedtls_entropy_init(&entropy);
    const char *pers = "rsa_dec";
    if (mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) != 0) {
        logMessage("[crypto] ctr seed failed decrypt");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    if (mbedtls_pk_parse_key(&pk, priv.data(), priv.size(), nullptr, 0) != 0) {
        logMessage("[crypto] decrypt: parse private key failed");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // decrypt encKey (RSA-OAEP-SHA256) explicitly
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        logMessage("[crypto] decrypt: private key is not RSA");
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    // if ( != 0) {
    //     logMessage("[crypto] decrypt: failed to set rsa padding");
    //     mbedtls_pk_free(&pk);
    //     mbedtls_ctr_drbg_free(&ctr);
    //     mbedtls_entropy_free(&entropy);
    //     return false;
    // }

    // aesKey output buffer: allocate modulus bytes
    size_t rsa_len = mbedtls_pk_get_len(&pk);
    std::vector<uint8_t> aesKey(rsa_len);
    size_t olen = 0;
    int rc = mbedtls_rsa_rsaes_oaep_decrypt(rsa,
            mbedtls_ctr_drbg_random, &ctr,
            MBEDTLS_RSA_PRIVATE,
            nullptr, 0,
            &olen,
            encKey.data(), aesKey.data(), aesKey.size());
    if (rc != 0) {
        fLogMessage("[crypto] oaep decrypt failed: -0x%04x\n", -rc);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }
    aesKey.resize(olen); // actual AES key length (should be 16)

    // use AES-GCM to decrypt
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey.data(), aesKey.size()*8) != 0) {
        logMessage("[crypto] gcm_setkey failed decrypt");
        mbedtls_gcm_free(&gcm);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    outCleartext.resize(ct_len);
    rc = mbedtls_gcm_auth_decrypt(&gcm, ct_len, nonce, GCM_NONCE_LEN, nullptr, 0, tag_ptr, GCM_TAG_LEN, ct_ptr, outCleartext.data());
    if (rc != 0) {
        fLogMessage("[crypto] gcm_auth_decrypt failed: -0x%04x\n", -rc);
        mbedtls_gcm_free(&gcm);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // cleanup
    mbedtls_gcm_free(&gcm);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    return true;
}
