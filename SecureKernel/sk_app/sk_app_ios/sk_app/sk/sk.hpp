//
//  sk.hpp
//  sk_app
//
//  Created by main on 2023-09-15.
//

#ifndef sk_hpp
#define sk_hpp

#include <stdio.h>
#include <cstddef>
#include <cstdint>

extern "C" {
    void sk_call(const uint8_t* inData, size_t inDataLen, uint8_t* outData, size_t* outDataLen);
}

#endif /* sk_hpp */
