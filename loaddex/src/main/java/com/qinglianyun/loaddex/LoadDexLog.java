package com.qinglianyun.loaddex;

import android.util.Log;

/**
 * Created by tang_xqing on 2021/3/9.
 */
public class LoadDexLog {
    public static final String TAG = LoadDexLog.class.getSimpleName();

    public static void print() {
        Log.d(TAG, "print() called  动态加载dex");
    }
}
