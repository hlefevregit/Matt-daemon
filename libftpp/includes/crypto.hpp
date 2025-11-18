/* Simple OpenSSL-based crypto helpers for X25519 ECDH and AES-256-GCM
 * Provides key generation, shared secret derivation and encrypt/decrypt helpers
 */
#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace ftcrypto {

// Generate an X25519 keypair. pub and priv will be filled with 32 bytes.
bool generate_x25519_keypair(std::vector<unsigned char>& pub, std::vector<unsigned char>& priv);

// Derive shared secret from our private key and peer public key (raw 32-byte keys)
bool derive_x25519_shared(const std::vector<unsigned char>& priv, const std::vector<unsigned char>& peer_pub, std::vector<unsigned char>& shared);

// Derive a symmetric key from the shared secret using HKDF-SHA256
bool hkdf_sha256(const std::vector<unsigned char>& secret, const std::string& info, std::vector<unsigned char>& out_key, size_t out_len);

// AES-256-GCM encrypt/decrypt helpers. Nonce is derived from a 64-bit counter: 12-byte nonce = 4 bytes zero + 8-byte BE counter
bool aes256gcm_encrypt(const unsigned char key[32], uint64_t counter, const unsigned char* plaintext, size_t plen, std::vector<unsigned char>& out_cipher, std::vector<unsigned char>& out_tag);
bool aes256gcm_decrypt(const unsigned char key[32], uint64_t counter, const unsigned char* cipher, size_t clen, const unsigned char* tag, size_t taglen, std::vector<unsigned char>& out_plain);

// Compute raw public key (32 bytes) from a raw private key (32 bytes)
bool raw_public_from_private(const std::vector<unsigned char>& priv, std::vector<unsigned char>& pub);

// PEM load/save helpers for server key (PEM file contains PKCS8 private key)
bool save_private_key_pem(const std::string& path, const std::vector<unsigned char>& priv_raw);
bool load_private_key_pem(const std::string& path, std::vector<unsigned char>& priv_raw);

}
