#include <jni.h>
#include <string>
#include <unistd.h>
#include <android/log.h>
#include <fcntl.h>
#include <asm/fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <linux/ptrace.h>
#include <sys/ptrace.h>

//import c header
extern "C" {
#include "hook/dlfcn/dlfcn_compat.h"
#include "hook/include/inlineHook.h"
}

typedef unsigned char byte;
#define TAG "SecondShell"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

struct DexFile {
    // Field order required by test "ValidateFieldOrderOfJavaCppUnionClasses".
    // The class we are a part of.
    uint32_t declaring_class_;
    // Access flags; low 16 bits are defined by spec.
    void *begin;
    /* Dex file fields. The defining dex file is available via declaring_class_->dex_cache_ */
    // Offset to the CodeItem.
    uint32_t size;
};
struct ArtMethod {
    // Field order required by test "ValidateFieldOrderOfJavaCppUnionClasses".
    // The class we are a part of.
    uint32_t declaring_class_;
    // Access flags; low 16 bits are defined by spec.
    uint32_t access_flags_;
    /* Dex file fields. The defining dex file is available via declaring_class_->dex_cache_ */
    // Offset to the CodeItem.
    uint32_t dex_code_item_offset_;
    // Index into method_ids of the dex file associated with this method.
    uint32_t dex_method_index_;
};

void **(*oriexecve)(const char *__file, char *const *__argv, char *const *__envp);

void **myexecve(const char *__file, char *const *__argv, char *const *__envp) {
    LOGD("process:%d,enter execve:%s", getpid(), __file);
    if (strstr(__file, "dex2oat")) {
        return NULL;
    } else {
        return oriexecve(__file, __argv, __envp);
    }
}

//void ClassLinker::LoadMethod(Thread* self, const DexFile& dex_file, const ClassDataItemIterator& it,Handle<mirror::Class> klass, ArtMethod* dst)
//        art::ClassLinker::LoadMethod(art::DexFile const&, art::ClassDataItemIterator const&, art::Handle<art::mirror::Class>, art::ArtMethod*)
void *(*oriloadmethod)(void *, void *, void *, void *, void *);

void *myloadmethod(void *a, void *b, void *c, void *d, void *e) {
    LOGD("process:%d,before run loadmethod:", getpid());
    struct ArtMethod *artmethod = (struct ArtMethod *) e;
    struct DexFile *dexfile = (struct DexFile *) b;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d", getpid(), dexfile->begin,
         dexfile->size);//0,57344

    //dump dex first time
    char dexfilepath[100] = {0};
    sprintf(dexfilepath, "/sdcard/5/%d_%d.dex", dexfile->size, getpid());
    int fd = open(dexfilepath, O_CREAT | O_RDWR, 0666);
    if (fd > 0) {
        write(fd, dexfile->begin, dexfile->size);
        close(fd);
    }

    void *result = oriloadmethod(a, b, c, d, e);
    LOGD("process:%d,enter loadmethod:code_offset:%d,idx:%d", getpid(),
         artmethod->dex_code_item_offset_, artmethod->dex_method_index_);

    byte *code_item_addr = static_cast<byte *>(dexfile->begin) + artmethod->dex_code_item_offset_;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,beforedumpcodeitem:%p", getpid(),
         dexfile->begin, dexfile->size, code_item_addr);


    // 这里是找到需要回填函数的method 位置
    if (artmethod->dex_method_index_ == 15459) {//LoadDexLog.print->methodidx
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,start repire method", getpid(),
             dexfile->begin, dexfile->size);
        byte *code_item_addr = (byte *) dexfile->begin + artmethod->dex_code_item_offset_;
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,beforedumpcodeitem:%p", getpid(),
             dexfile->begin, dexfile->size, code_item_addr);

        int result = mprotect(dexfile->begin, dexfile->size, PROT_WRITE);

        byte *code_item_start = static_cast<byte *>(code_item_addr) + 16;
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,code_item_start:%p", getpid(),
             dexfile->begin, dexfile->size, code_item_start);
//        byte inst[16] = {0x1a, 0x00, 0xed, 0x34, 0x1a, 0x01, 0x43, 0x32, 0x71, 0x20, 0x91, 0x05,0x10, 0x00, 0x0e, 0x00};

        // 这里是函数回填的内容
        byte inst[16] = {0x62, 0x00, 0x50, 0x25, 0x1A, 0x01, 0xB6, 0x44, 0x71, 0x20, 0x9C, 0x05,
                         0x10, 0x00, 0x0E, 0x00};
        for (int i = 0; i < sizeof(inst); i++) {
            code_item_start[i] = inst[i];
        }

        //second dump dex
        memset(dexfilepath, 0, 100);
        sprintf(dexfilepath, "/sdcard/5/%d_%d_after.dex", dexfile->size, getpid());
        fd = open(dexfilepath, O_CREAT | O_RDWR, 0666);
        if (fd > 0) {
            write(fd, dexfile->begin, dexfile->size);
            close(fd);
        }
    }
    LOGD("process:%d,after loadmethod:code_offset:%d,idx:%d", getpid(),
         artmethod->dex_code_item_offset_, artmethod->dex_method_index_);//0,57344
    return result;

}

/*
* 禁用dex2oat，hook
*/
void hooklibc() {
    LOGD("go into hooklibc");
    //7.0 命名空间限制
    void *libc_addr = dlopen_compat("libc.so", RTLD_NOW);
    void *execve_addr = dlsym_compat(libc_addr, "execve");
    if (execve_addr != NULL) {
        if (ELE7EN_OK == registerInlineHook((uint32_t) execve_addr, (uint32_t) myexecve,
                                            (uint32_t **) &oriexecve)) {
            if (ELE7EN_OK == inlineHook((uint32_t) execve_addr)) {
                LOGD("inlineHook execve success");
            } else {
                LOGD("inlineHook execve failure");
            }
        }
    }
}

void hookART() {
    LOGD("go into hookART");
    void *libart_addr = dlopen_compat("/system/lib/libart.so", RTLD_NOW);
    if (libart_addr != NULL) {
        void *loadmethod_addr = dlsym_compat(libart_addr,
                                             "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
//        _ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE

        if (loadmethod_addr != NULL) {
            if (ELE7EN_OK == registerInlineHook((uint32_t) loadmethod_addr, (uint32_t) myloadmethod,
                                                (uint32_t **) &oriloadmethod)) {
                if (ELE7EN_OK == inlineHook((uint32_t) loadmethod_addr)) {
                    LOGD("inlineHook loadmethod success");
                } else {
                    LOGD("inlineHook loadmethod failure");
                }
            }
        }
    }
}

const char *getFieldValue(JNIEnv *env) {
    // 调用java函数
    jclass jclass1 = env->FindClass("com/qinglianyun/dexstudy/MainActivity");
    if (nullptr == jclass1) {
        LOGD("find class error");
        return "";
    }
    jfieldID fieldId = env->GetStaticFieldID(jclass1, "NATIVA_STR", "Ljava/lang/String;");
    if (nullptr == fieldId) {
        LOGD("find field error");
        return "";
    }
    if (env->ExceptionCheck()) {
        return "";
    }
    jstring nativeStr = static_cast<jstring>(env->GetStaticObjectField(jclass1, fieldId));
    const char *value = env->GetStringUTFChars(nativeStr, JNI_FALSE);
//    LOGD("field value = ", value);
    return value;
}

const char *get_packagename(JNIEnv *env, jobject context) {
    jclass content_class = env->FindClass("android/content/Context");
    if (content_class == nullptr) {
        printf("find class error");
        return "";
    }
    jmethodID getPackageName_method = env->GetMethodID(content_class, "getPackageName",
                                                       "()Ljava/lang/String;");
    if (getPackageName_method == nullptr) {
        printf("find method error");
        return "";
    }
    if (env->ExceptionCheck()) {
        return "";
    }
    jstring pkgname_string = (jstring) env->CallObjectMethod(context, getPackageName_method);
    const char *ret = env->GetStringUTFChars(pkgname_string,
                                             JNI_FALSE);
    printf("pkgname => %s", ret);
    return ret;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_qinglianyun_dexstudy_MainActivity_stringFromJNIWithContext(JNIEnv *env,
                                                                    jobject /* this */ jobj,
                                                                    jobject context) {
    std::string hello = "Hello from C++";
    printf("Hello from C++ => %s", hello.c_str());
    for (int i = 0; i < hello.length(); i++) {
        hello[i] = hello[i] ^ hello.length();
    }
    printf("Hello from C++ => %s", hello.c_str());
    const char *pkgname = get_packagename(env, context);

    if (strcmp(pkgname, "com.qinglianyun.dexstudy") != -1) {
        printf("pkg name => %s", pkgname);
    }
//    return env->NewStringUTF(hello.c_str());
    return env->NewStringUTF(pkgname);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_qinglianyun_dexstudy_MainActivity_stringFromJNI(JNIEnv *env, jobject /* this */,
                                                         jstring value) {
//    std::string hello = "ART SecondShell +";
//    return env->NewStringUTF(hello.c_str());

// GetStringUTFChars() 从jvm开辟一块新的空间，用来存储字符串的拷贝，以便本地使用；C语言中需要自己管理内存。所以使用GetxxxUTFChars() 后，必须要主动调用ReleaseStringUTFChars()通知JVM 使用这部分的内存空间。
    const char *c = env->GetStringUTFChars(value, 0);
    env->ReleaseStringUTFChars(value, c);

//    env->GetStringChars(value)  // 获取unicode字符串
    jsize length = env->GetStringLength(value);
    jchar *pBuff;
    // 预先分配一个缓存区，GetStringRegion不会分配新的内存空间，所以没有release
    env->GetStringRegion(value, 0, length, pBuff);


    // 返回字符串指针。不能调用阻塞线程的方法或者分配新的对象，因为暂停了jvm的回收，会导致整体阻塞。
    const jchar *str = env->GetStringCritical(value, 0);

    return value;
}

extern "C" JNIEXPORT void JNICALL
Java_com_qinglianyun_dexstudy_MainActivity_SecondShell(JNIEnv *env, jobject /* this */) {
    /*
    * 步骤：
        1.禁用dex2oat使其不进入dex2oat流程，实现方式：hook execve();
        2.hook ArtMethod，找到ClassLinker的LoadMethod 符号，然后进行函数方法体回填
    */
    hooklibc();
    hookART();
    return;
}

// public native String accessRequestDisgen(byte[] array, int len);

jstring onAccexxRequestDisgen(
        JNIEnv *env,
        jobject obj) {
    std::string hello = "on Accexx Request Disgen";

    // 测试
    char str[] = "Hello,中国!";
    char oldstr[] = "";
    char newstr[] = "";
    char bstr[strlen(str)];//转换缓冲区
    memset(bstr, 0, sizeof(bstr));

    for (int i = 0; i < strlen(str); i++) {
        if (!strncmp(str + i, oldstr, strlen(oldstr))) {//查找目标字符串
            strcat(bstr, newstr);
            i += strlen(oldstr) - 1;
        } else {
            strncat(bstr, str + i, 1);//保存一字节进缓冲区
        }
    }

    strcpy(str, bstr);

    return env->NewStringUTF(hello.c_str());
}

/**
 * 将java层的函数进行native化。
 *  下面演示onCrate()native化，需要注意的是，方法和属性的签名按照smali语法。
 * @param env
 * @param jobj
 * @param savedInstanceState
 */
void CreateNative(JNIEnv *env, jobject jobj, jobject savedInstanceState) {

    jclass Activity = env->FindClass("android/app/Activity");

    //    super.onCreate(savedInstanceState);
    jmethodID onCreateID = env->GetMethodID(Activity, "onCreate", "(Landroid/os/Bundle;)V");
    // CallNonvirtual XXX Method 一系列函数用来调用父类方法。
    env->CallNonvirtualVoidMethod(jobj, Activity, onCreateID, savedInstanceState);

    //    setContentView(R.layout.activity_main);
    jclass R = env->FindClass("com/qinglianyun/dexstudy/R$layout");
    jfieldID activity_main_id = env->GetStaticFieldID(R, "activity_main", "I");
    jint activity_main_value = env->GetStaticIntField(R, activity_main_id);
    jmethodID setContentViewId = env->GetMethodID(Activity, "setContentView", "(I)V");
    env->CallVoidMethod(jobj, setContentViewId, activity_main_value);


    // Toast.makeText(this, getContent(), Toast.LENGTH_SHORT).show();
    jclass Toast = env->FindClass("android/widget/Toast");
    jmethodID makeTextId = env->GetStaticMethodID(Toast, "makeText",
                                                  "(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;");
    jmethodID showID = env->GetMethodID(Toast, "show", "()V");

    jfieldID LENGTH_SHORT_ID = env->GetStaticFieldID(Toast, "LENGTH_SHORT", "I");
    jint LENGTH_SHORT = env->GetStaticIntField(Toast, LENGTH_SHORT_ID);

    jstring value = env->NewStringUTF("我来自native层");
    jobject toastObj = env->CallStaticObjectMethod(Toast, makeTextId, jobj, value, LENGTH_SHORT);
    env->CallVoidMethod(toastObj, showID);
}

jstring onCallJavaField(JNIEnv *env, jobject jobj) {

//    return env->NewStringUTF(getFieldValue(env,env->GetObjectClass(jobj)));
    return env->NewStringUTF(getFieldValue(env));
}

JNINativeMethod nativeMethod[] = {
        // JNINativeMethod 结构体：第一个参数：java端方法名；第二个参数：方法签名；第三个参数：native层对应的方法（括号内表示方法返回值）
        {"accexxRequestDisgen", "()Ljava/lang/String;",   (jstring *) onAccexxRequestDisgen},
        {"callJavaField",       "()Ljava/lang/String;",   (jstring *) onCallJavaField},
        {"onCreate",            "(Landroid/os/Bundle;)V", (void *) CreateNative}
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint ret = vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    if (ret != JNI_OK) {
        return -1;
    }
    // PTRACE_TRACEME 本进程被其父进程所跟踪，其父进程应该希望跟踪子进程，一般进程只被跟踪一次
//    ptrace(PTRACE_TRACEME,0,0,0);

    jclass jclass1 = env->FindClass("com/qinglianyun/dexstudy/MainActivity");
    if (jclass1 == NULL) {
        return -1;
    }
    // 动态注册jni函数，简化静态注册jni函数名。
    ret = env->RegisterNatives(jclass1, nativeMethod,
                               sizeof(nativeMethod) / sizeof(nativeMethod[0]));
    if (ret != JNI_OK) {
        return -1;
    }

    // 返回java版本
    return JNI_VERSION_1_6;
}