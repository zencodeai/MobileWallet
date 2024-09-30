//
//  sk.cpp
//  sk_app
//
//  Created by main on 2023-09-15.
//

#include "sk.hpp"

void sk_call(const uint8_t* inData, size_t inDataLen, uint8_t* outData, size_t* outDataLen) {
    // Your logic here
    // As an example: let's copy inData to outData and set the length
    *outDataLen = inDataLen;
    for(size_t i = 0; i < inDataLen; i++) {
        outData[i] = inData[i];
    }
}

