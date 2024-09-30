#include <jni.h>

#include "sk.h"

// Reference to main activity (global reference)
jobject g_main_activity = nullptr;

// Reference to JVM
JavaVM *g_jvm = nullptr;

extern "C" {

// Define the sk_call function
void _sk_call(const unsigned char *in, const size_t in_len, unsigned char *out, size_t *out_len) {
    // For this example, I'm just copying the input to the output.
    // Replace this with your actual logic.
    if (*out_len >= in_len) {
        for (size_t i = 0; i < in_len; i++) {
            out[i] = in[i];
        }
        *out_len = in_len;
    } else {
        // Handle error: output buffer too small.
        *out_len = 0;
    }
}

JNIEXPORT void JNICALL
Java_com_example_sk_1app_MainActivity_skCall(JNIEnv *env, jobject thiz, jbyteArray in_data,
                                             jint in_len, jbyteArray out_data, jintArray out_len) {

    // Set reference to main activity
    if (g_main_activity == nullptr) {

        g_main_activity = env->NewGlobalRef(thiz);
    }

    // Set reference to JVM
    if (g_jvm == nullptr) {

        env->GetJavaVM(&g_jvm);
    }

    // Invoke the sk_call function
    auto *in = (unsigned char *) env->GetByteArrayElements(in_data, nullptr);
    auto *out = (unsigned char *) env->GetByteArrayElements(out_data, nullptr);
    size_t out_len_ = (size_t) env->GetIntArrayElements(out_len, nullptr)[0];
    sk_call(in, (size_t) in_len, out, &out_len_);
    env->ReleaseByteArrayElements(in_data, (jbyte *) in, JNI_ABORT);
    env->ReleaseByteArrayElements(out_data, (jbyte *) out, 0);
    // Return the output length
    env->SetIntArrayRegion(out_len, 0, 1, (jint *) &out_len_);
}

} // extern "C"
