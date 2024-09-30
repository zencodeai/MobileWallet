
#include <math.h>
#include <iostream>

#include "skt_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"

// Measuree shannon entropy of a byte array
double measure_entropy(const SKBinaryBuffer& buffer) {

    // Calculate frequency of each byte value
    uint32_t frequency[256] = { 0 };
    for (uint32_t i = 0; i < buffer.GetSize(); i++) {
        frequency[buffer.GetBuffer()[i]]++;
    }

    // Calculate entropy
    double entropy = 0.0;
    for (uint32_t i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / (double)buffer.GetSize();
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

// Secure store test entry point.
int test_skt_random(int, char*[]) {

    // Secure store pathname
    const std::string pathname = "test.sqlite";

    try {

        // Delete secure store using stl
        std::remove(pathname.c_str());

        // Instantiate secure store
        SKSecureStorePtr spstore = SKSecureStore::Create();

        // Create secure store
        spstore->Create(pathname.c_str());

        // Instantiate random number generator
        SKRandomPtr sprandom = SKRandom::Create(spstore);

        // Generate random byte string of length 32
        SKStaticBinaryBuffer<32> buffer;
        buffer.SetSize(32);
        generate_random_bytes(buffer.GetBuffer(), buffer.GetSize());

        // Update seed
        sprandom->UpdateSeed(buffer);

        // Repeat 100 times
        for (uint32_t i = 0; i < 100; i++) {

            // Generate random byte string of length 32
            SKDynamicBinaryBuffer seq;
            sprandom->Generate(1024, seq);

            // Measure entropy
            double entropy = measure_entropy(seq);
            SK_CHECK(entropy > 7.5 && entropy < 8.1, SK_ERROR_FAILED, "Entropy out of range: %f", entropy);

            // Restore state
            if (!(i % 32)) sprandom->RestoreState();
        }
    }
    catch (SKException& error) {
        std::cout << "Error: " << error.what() << std::endl;
        return 1;
    }

    catch (std::exception& error) {
        std::cout << "Error: " << error.what() << std::endl;
        return 1;
    }

    catch (...) {
        std::cout << "Error: Unknown exception" << std::endl;
        return 1;
    }

    return 0;
}
