#include <Foundation/Foundation.h>

@interface SKWrapper : NSObject

+ (void)callWithData:(NSData *)inData outData:(NSMutableData **)outData;

@end
