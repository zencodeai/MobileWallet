#include "sk_utils_platform.hpp"

#include <string>
#include <cstdlib>

// iOS implementation, get the path to the store file
std::string SKGetStoreFilePath(const char* filename) {

    // Get HOME environment variable
    const char* home = getenv("HOME");
    if (home == nullptr) {
        return std::string(filename);
    }

    return std::string(home) + "/Documents/" + filename;
}
