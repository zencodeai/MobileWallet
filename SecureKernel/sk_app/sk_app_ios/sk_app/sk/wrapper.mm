#import "wrapper.h"
#import "sk.hpp"

@implementation SKWrapper

+ (void)callWithData:(NSData *)inData outData:(NSMutableData **)outData {
    size_t outDataLen = 2048;
    uint8_t outBuffer[2048];  // You may need to adjust buffer size based on your logic
    
    sk_call((const uint8_t*)inData.bytes, inData.length, outBuffer, &outDataLen);
    
    *outData = [NSMutableData dataWithBytes:outBuffer length:outDataLen];
}

@end
