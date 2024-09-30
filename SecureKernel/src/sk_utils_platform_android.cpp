#include "sk_utils_platform.hpp"

#include <jni.h>

// Reference to main activity (global reference)
extern jobject g_main_activity;

// Reference to JVM
extern JavaVM *g_jvm;

// Get main activity
jobject SKGetMainActivity() {

    SK_CHECK(g_main_activity != nullptr, SK_ERROR_FAILED, "Main activity not set");
    return g_main_activity;
}

// Get java VM reference
JavaVM* SKGetJavaVM() {

    SK_CHECK(g_jvm != nullptr, SK_ERROR_FAILED, "Java VM not set");
    return g_jvm;
}

// JEnv class
class SKJEnv {

private:

    // JNIEnv instance
    JNIEnv* m_env;

    // Thread attached
    bool m_attached;

public:

    // Constructor
    SKJEnv() {

        // Get JNIEnv instance
        m_env = nullptr;
        m_attached = false;
        JavaVM* jvm = SKGetJavaVM();
        jint res = jvm->GetEnv((void**) &m_env, JNI_VERSION_1_6);

        // Check if thread is attached
        if (res == JNI_EDETACHED) {

            // Attach thread
            res = jvm->AttachCurrentThread(&m_env, nullptr);
            SK_CHECK(res == JNI_OK, SK_ERROR_FAILED, "AttachCurrentThread failed: %d", res);
            m_attached = true;
        }

        SK_CHECK(res == JNI_OK, SK_ERROR_FAILED, "GetEnv failed: %d", res);
    }

    // Destructor
    ~SKJEnv() {

        // Detach thread
        if (m_attached) {
            JavaVM* jvm = SKGetJavaVM();
            jvm->DetachCurrentThread();
        }
    }

    // Get JNIEnv instance
    inline JNIEnv* GetEnv() {

        return m_env;
    }
};

// Get path to application data directory using JNI
std::string SKGetStoreFilePath(const char* filename) {

    thread_local SKJEnv env;

    // Get main activity class
    jclass activity_class = env.GetEnv()->GetObjectClass(SKGetMainActivity());
    SK_CHECK(activity_class != nullptr, SK_ERROR_FAILED, "GetObjectClass failed");

    // Get getFilesDir method
    jmethodID get_files_dir_method = env.GetEnv()->GetMethodID(activity_class, "getFilesDir", "()Ljava/io/File;");
    SK_CHECK(get_files_dir_method != nullptr, SK_ERROR_FAILED, "GetMethodID failed");

    // Invoke getFilesDir method
    jobject files_dir = env.GetEnv()->CallObjectMethod(SKGetMainActivity(), get_files_dir_method);
    SK_CHECK(files_dir != nullptr, SK_ERROR_FAILED, "CallObjectMethod failed");

    jclass files_dir_class = env.GetEnv()->GetObjectClass(files_dir);
    SK_CHECK(files_dir_class != nullptr, SK_ERROR_FAILED, "GetObjectClass failed");

    jmethodID get_path_method = env.GetEnv()->GetMethodID(files_dir_class, "getPath", "()Ljava/lang/String;");
    SK_CHECK(get_path_method != nullptr, SK_ERROR_FAILED, "GetMethodID failed");

    jstring path = (jstring) env.GetEnv()->CallObjectMethod(files_dir, get_path_method);
    SK_CHECK(path != nullptr, SK_ERROR_FAILED, "CallObjectMethod failed");

    // Convert to string
    const char* path_str = env.GetEnv()->GetStringUTFChars(path, nullptr);
    std::string path_str2(path_str);
    env.GetEnv()->ReleaseStringUTFChars(path, path_str);

    // Return path
    return path_str2 + "/" + filename;
}
