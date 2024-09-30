#include "sk_utils_platform.hpp"

// OSX/Linux desktop test implementation, just return the filename
std::string SKGetStoreFilePath(const char* filename) {

    return std::string(filename);
}
