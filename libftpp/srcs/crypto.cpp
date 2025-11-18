#include "../includes/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring>
#include <fstream>

namespace ftcrypto {

static void openssl_init_once()
{
    static bool inited = false;
    if (!inited) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        inited = true;
    }
}

bool generate_x25519_keypair(std::vector<unsigned char>& pub, std::vector<unsigned char>& priv)
{
    openssl_init_once();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return false;
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY_CTX_free(pctx);

    size_t priv_len = 0, pub_len = 0;
    EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len);
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len);
    if (priv_len != 32 || pub_len != 32) { EVP_PKEY_free(pkey); return false; }

    priv.resize(priv_len);
    pub.resize(pub_len);
    if (EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len) <= 0) { EVP_PKEY_free(pkey); return false; }
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len) <= 0) { EVP_PKEY_free(pkey); return false; }

    EVP_PKEY_free(pkey);
    return true;
}

bool derive_x25519_shared(const std::vector<unsigned char>& priv, const std::vector<unsigned char>& peer_pub, std::vector<unsigned char>& shared)
{
    openssl_init_once();
    EVP_PKEY *priv_k = NULL;
    EVP_PKEY *peer_k = NULL;
    priv_k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv.data(), priv.size());
    if (!priv_k) return false;
    peer_k = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub.data(), peer_pub.size());
    if (!peer_k) { EVP_PKEY_free(priv_k); return false; }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_k, NULL);
    if (!ctx) { EVP_PKEY_free(priv_k); EVP_PKEY_free(peer_k); return false; }
    if (EVP_PKEY_derive_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv_k); EVP_PKEY_free(peer_k); return false; }
    if (EVP_PKEY_derive_set_peer(ctx, peer_k) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv_k); EVP_PKEY_free(peer_k); return false; }
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv_k); EVP_PKEY_free(peer_k); return false; }
    shared.resize(secret_len);
    if (EVP_PKEY_derive(ctx, shared.data(), &secret_len) <= 0) { EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv_k); EVP_PKEY_free(peer_k); return false; }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_k);
    EVP_PKEY_free(peer_k);
    return true;
}

bool hkdf_sha256(const std::vector<unsigned char>& secret, const std::string& info, std::vector<unsigned char>& out_key, size_t out_len)
{
    openssl_init_once();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return false;
    if (EVP_PKEY_derive_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    // no salt
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), (int)secret.size()) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char*)info.data(), (int)info.size()) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    }
    out_key.resize(out_len);
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out_key.data(), &len) <= 0) { EVP_PKEY_CTX_free(pctx); return false; }
    EVP_PKEY_CTX_free(pctx);
    return true;
}

bool raw_public_from_private(const std::vector<unsigned char>& priv, std::vector<unsigned char>& pub)
{
    openssl_init_once();
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv.data(), priv.size());
    if (!pkey) return false;
    size_t pub_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_len) != 1) { EVP_PKEY_free(pkey); return false; }
    pub.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len) != 1) { EVP_PKEY_free(pkey); return false; }
    EVP_PKEY_free(pkey);
    return true;
}

static void build_nonce(uint64_t counter, unsigned char out[12])
{
    // 12-byte nonce: 4 bytes zero + 8-byte big-endian counter
    out[0]=out[1]=out[2]=out[3]=0;
    for (int i=0;i<8;i++) out[11-i] = (unsigned char)((counter >> (8*i)) & 0xff);
}

bool aes256gcm_encrypt(const unsigned char key[32], uint64_t counter, const unsigned char* plaintext, size_t plen, std::vector<unsigned char>& out_cipher, std::vector<unsigned char>& out_tag)
{
    openssl_init_once();
    unsigned char iv[12];
    build_nonce(counter, iv);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    int outlen = 0;
    out_cipher.clear();
    out_cipher.resize(plen);
    if (plen>0) {
        if (!plaintext) { fprintf(stderr, "aes256gcm_encrypt: plaintext == NULL but plen=%zu\n", plen); ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
        fprintf(stderr, "aes256gcm_encrypt: counter=%llu plen=%zu key0=%02x\n", (unsigned long long)counter, plen, (unsigned char)key[0]);
        if (EVP_EncryptUpdate(ctx, out_cipher.data(), &outlen, plaintext, (int)plen) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
        // resize in case OpenSSL wrote less than plen
        out_cipher.resize(outlen);
    }
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, NULL, &tmplen) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    out_tag.assign(tag, tag+16);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes256gcm_decrypt(const unsigned char key[32], uint64_t counter, const unsigned char* cipher, size_t clen, const unsigned char* tag, size_t taglen, std::vector<unsigned char>& out_plain)
{
    openssl_init_once();
    unsigned char iv[12];
    build_nonce(counter, iv);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ERR_print_errors_fp(stderr); return false; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    int outlen = 0;
    out_plain.clear();
    out_plain.resize(clen);
    if (clen>0) {
        if (EVP_DecryptUpdate(ctx, out_plain.data(), &outlen, cipher, (int)clen) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
        out_plain.resize(outlen);
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)taglen, (void*)tag) != 1) { ERR_print_errors_fp(stderr); EVP_CIPHER_CTX_free(ctx); return false; }
    int ret = EVP_DecryptFinal_ex(ctx, NULL, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return ret==1;
}

bool save_private_key_pem(const std::string& path, const std::vector<unsigned char>& priv_raw)
{
    // Create EVP_PKEY from raw private key and write PEM
    openssl_init_once();
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_raw.data(), priv_raw.size());
    if (!pkey) return false;
    BIO *bio = BIO_new_file(path.c_str(), "w");
    if (!bio) { EVP_PKEY_free(pkey); return false; }
    bool ok = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) == 1;
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return ok;
}

bool load_private_key_pem(const std::string& path, std::vector<unsigned char>& priv_raw)
{
    openssl_init_once();
    BIO *bio = BIO_new_file(path.c_str(), "r");
    if (!bio) return false;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return false;
    size_t priv_len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len) != 1) { EVP_PKEY_free(pkey); return false; }
    priv_raw.resize(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, priv_raw.data(), &priv_len) != 1) { EVP_PKEY_free(pkey); return false; }
    EVP_PKEY_free(pkey);
    return true;
}

}
