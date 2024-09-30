#ifndef __SK_H__
#define __SK_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define EXPORT __attribute__((visibility("default")))

/* Secure kernel API  */
EXPORT void sk_call(const unsigned char* in, const size_t in_len, unsigned char* out, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif // __SK_H__
