#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <openssl/ec.h>

#define REPORT_DATA_SIZE 64

namespace accless::attestation::ec {
class EcKeyPair {
  public:
    EcKeyPair();
    ~EcKeyPair();

    EcKeyPair(const EcKeyPair &) = delete;
    EcKeyPair &operator=(const EcKeyPair &) = delete;

    /**
     * @brief Derives a shared secret from a public key.
     *
     * This function performs the second half of an EC Diffie-Helman key
     * exchange by derving a shared secret from the public counter-part of
     * another EC keypair.
     *
     * @param otherPubKey The public key of the other part involved in the exchange.
     * @return A byte-array with the shared secret.
     */
    std::vector<uint8_t> deriveSharedSecret(const std::vector<uint8_t> &otherPubKey) const;

    /**
     * @brief Generate the report data field for an extended attestation quote.
     *
     * This function generates the byte array that we embed in an extended
     * attestation quote with the serialized public counterpart of this EC
     * key pair. It relies on the fact that the auxiliary data field for SNP
     * and SGX reports is, currently, the same size (8 bytes).
     *
     * @return A byte-array with the additional report data.
     */
    std::array<uint8_t, REPORT_DATA_SIZE> getReportData() const;

    EC_KEY *get() const;

  private:
    EC_KEY *key_;
};

} // namespace accless::attestation::ec
