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


    // ????????????????????????????????????method ??????
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

        // ??????????????????????????????
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
* ??????dex2oat???hook
*/
void hooklibc() {
    LOGD("go into hooklibc");
    //7.0 ??????????????????
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
    // ??????java??????
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

// GetStringUTFChars() ???jvm?????????????????????????????????????????????????????????????????????????????????C????????????????????????????????????????????????GetxxxUTFChars() ???????????????????????????ReleaseStringUTFChars()??????JVM ?????????????????????????????????
    const char *c = env->GetStringUTFChars(value, 0);
    env->ReleaseStringUTFChars(value, c);

//    env->GetStringChars(value)  // ??????unicode?????????
    jsize length = env->GetStringLength(value);
    jchar *pBuff;
    // ??????????????????????????????GetStringRegion?????????????????????????????????????????????release
    env->GetStringRegion(value, 0, length, pBuff);


    // ???????????????????????????????????????????????????????????????????????????????????????????????????jvm????????????????????????????????????
    const jchar *str = env->GetStringCritical(value, 0);

    return value;
}

extern "C" JNIEXPORT void JNICALL
Java_com_qinglianyun_dexstudy_MainActivity_SecondShell(JNIEnv *env, jobject /* this */) {
    /*
    * ?????????
        1.??????dex2oat???????????????dex2oat????????????????????????hook execve();
        2.hook ArtMethod?????????ClassLinker???LoadMethod ??????????????????????????????????????????
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

    // ??????
    char str[] = "Hello,??????!";
    char oldstr[] = "";
    char newstr[] = "";
    char bstr[strlen(str)];//???????????????
    memset(bstr, 0, sizeof(bstr));

    for (int i = 0; i < strlen(str); i++) {
        if (!strncmp(str + i, oldstr, strlen(oldstr))) {//?????????????????????
            strcat(bstr, newstr);
            i += strlen(oldstr) - 1;
        } else {
            strncat(bstr, str + i, 1);//???????????????????????????
        }
    }

    strcpy(str, bstr);

    return env->NewStringUTF(hello.c_str());
}

/**
 * ???java??????????????????native??????
 *  ????????????onCrate()native?????????????????????????????????????????????????????????smali?????????
 * @param env
 * @param jobj
 * @param savedInstanceState
 */
void CreateNative(JNIEnv *env, jobject jobj, jobject savedInstanceState) {

    jclass Activity = env->FindClass("android/app/Activity");

    //    super.onCreate(savedInstanceState);
    jmethodID onCreateID = env->GetMethodID(Activity, "onCreate", "(Landroid/os/Bundle;)V");
    // CallNonvirtual XXX Method ??????????????????????????????????????????
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

    jstring value = env->NewStringUTF("?????????native???");
    jobject toastObj = env->CallStaticObjectMethod(Toast, makeTextId, jobj, value, LENGTH_SHORT);
    env->CallVoidMethod(toastObj, showID);
}

jstring onCallJavaField(JNIEnv *env, jobject jobj) {

//    return env->NewStringUTF(getFieldValue(env,env->GetObjectClass(jobj)));
    return env->NewStringUTF(getFieldValue(env));
}

JNINativeMethod nativeMethod[] = {
        // JNINativeMethod ??????????????????????????????java??????????????????????????????????????????????????????????????????native??????????????????????????????????????????????????????
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
    // PTRACE_TRACEME ????????????????????????????????????????????????????????????????????????????????????????????????????????????
//    ptrace(PTRACE_TRACEME,0,0,0);

    jclass jclass1 = env->FindClass("com/qinglianyun/dexstudy/MainActivity");
    if (jclass1 == NULL) {
        return -1;
    }
    // ????????????jni???????????????????????????jni????????????
    ret = env->RegisterNatives(jclass1, nativeMethod,
                               sizeof(nativeMethod) / sizeof(nativeMethod[0]));
    if (ret != JNI_OK) {
        return -1;
    }

    // ??????java??????
    return JNI_VERSION_1_6;
}