package com.qinglianyun.dexstudy;

import android.app.Application;
import android.util.Log;

/**
 * Created by tang_xqing on 2021/3/23.
 */
public class MyApplication extends Application {
    public final String TAG = MyApplication.class.getSimpleName();
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "onCreate() called");
    }
}
