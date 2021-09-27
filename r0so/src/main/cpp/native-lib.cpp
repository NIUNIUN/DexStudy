#include <jni.h>
#include <unistd.h>
#include <android/log.h>
#include <string>

bool myr0(char *a) {
    // strstr() 函数：查找字串，并返回首次出现时的地址
    if (strstr(a, "r0ysue") != nullptr) {
        __android_log_print(4, "MyHook", "I am success");
    } else {
        __android_log_print(4, "MyHook", "I am fail");
    }
    return strstr(a, "r0ysue");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_qinglianyun_r0so_MainActivity_print(JNIEnv *env, jobject /* this */,
                                             jstring value) {
    std::string hello = "hello, I am from C++";

    const char *conChar = env->GetStringUTFChars(value, 0);

    if (myr0(const_cast<char *>(conChar))) {
        __android_log_print(4, "MyHook", "is true");
    } else {
        __android_log_print(4, "MyHook", "is false");
    }
    return env->NewStringUTF(hello.c_str());
}
