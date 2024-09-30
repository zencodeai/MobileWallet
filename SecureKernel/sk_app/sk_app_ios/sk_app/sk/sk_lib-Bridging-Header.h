//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

#include <Foundation/Foundation.h>

@interface SKWrapper : NSObject

+ (void)callWithData:(NSData *)inData outData:(NSMutableData **)outData;

@end
