package com.qinglianyun.dexstudy;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import dalvik.system.DexClassLoader;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Debug;
import android.util.ArrayMap;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI(String value);

    public native String stringFromJNIWithContext(Context context);

    public native void SecondShell();

    public native String accexxRequestDisgen();

    public native String callJavaField();

    public void callJNI(View view) {
        Toast.makeText(this, getContent(), Toast.LENGTH_SHORT).show();
    }

    public void callJNITwo(View view) {
        boolean debuggerConnected = Debug.isDebuggerConnected();

        Base64.decode("", 0);

        Toast.makeText(this, accexxRequestDisgen(), Toast.LENGTH_SHORT).show();
    }

    public String getContent() {
        return stringFromJNI("123sdf");
    }

    public static String NATIVA_STR = "11554_fass";

    protected native void onCreate(Bundle savedInstanceState);

    /*  @Override
      protected void onCreate(Bundle savedInstanceState) {
          super.onCreate(savedInstanceState);
          setContentView(R.layout.activity_main);

          checkPermission();

          Toast.makeText(this, "ddd "+callJavaField(), Toast.LENGTH_SHORT).show();

  //        String dexPath = "/sdcard/5/loaddex_modify.dex";
          String dexPath = "/sdcard/5/2152752_9371_after.dex";

          Thread thread= new Thread();
          thread.start();
          thread.interrupt();

  //        SecondShell();

          // 简单的动态加载，调用普通方法
  //        loadDex(dexPath);

          // 简单的动态加载，错误调用Activity
  //        loadActivityErr(dexPath);

          // 动态加载，修正ClassLoader修改，正确调用Activity
  //        loadActivityFirstByReplace(dexPath);

          // 动态加载，修正ClassLoader修改，正确调用Activity
  //        loadActivitySecondByInsert(dexPath);

          String packageName = getPackageName();
          Log.e("测试 ","packageName = "+packageName);

          int identifier = getResources().getIdentifier("main_tv_call", "id", packageName);
          Log.e("测试 ","identifier = "+identifier);

      }
  */

    private void loadDex(String dexPath) {
        String optPath = getDir("dex_opt", 0).getAbsolutePath();
        String libPath = getDir("dex_lib", 0).getAbsolutePath();

        ClassLoader classLoader = getClassLoader().getParent();
        DexClassLoader loader = new DexClassLoader(dexPath, optPath, libPath, classLoader);

        try {
            /**
             * 显示加载类。通过反射调用方法
             */
            Class<?> loadClass = loader.loadClass("com.qinglianyun.loaddex.LoadDexLog");
            if (null != loadClass) {
                Object instance = loadClass.newInstance();

                Method method = loadClass.getDeclaredMethod("print");
                method.invoke(instance);
            }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }

    private void loadActivityErr(String dexPath) {
        String optPath = getDir("dex_opt", 0).getAbsolutePath();
        String libPath = getDir("dex_lib", 0).getAbsolutePath();

        ClassLoader classLoader = getClassLoader().getParent();
        DexClassLoader loader = new DexClassLoader(dexPath, optPath, libPath, classLoader);

        try {
            /**
             * 显示加载类。通过反射调用方法
             */
            Class<?> loadClass = loader.loadClass("com.qinglianyun.loaddex.MainActivity");

            if (null != loadClass) {

                /**
                 * 启动Activity会报错，说明能够加载Activity，只是不能执行。
                 * 因为Activity属于系统组件，有自己的生命周期，有系统的回调控制。
                 */
                Intent intent = new Intent(this, loadClass);
                startActivity(intent);
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 主要是在应用启动类ActivityThread中，mPackages 字段域
     * <p>
     * final ArrayMap<String, WeakReference<LoadedApk>> mPackages = new ArrayMap<>();
     *
     * @param classLoader
     */
    private void replaceClassLoader(ClassLoader classLoader) {
        try {
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method threadClassMethod = activityThreadClass.getMethod("currentActivityThread");
            threadClassMethod.setAccessible(true);
            // 调用currentActivityThread() 方法
            Object currentActivityThread = threadClassMethod.invoke(null);


            Field mPackagesField = activityThreadClass.getDeclaredField("mPackages");
            mPackagesField.setAccessible(true);
            // 获取类到字段
            ArrayMap packages = (ArrayMap) mPackagesField.get(currentActivityThread);
            WeakReference o = (WeakReference) packages.get(this.getPackageName());
            Object loadApkClassLoader = o.get();
            // LoadedApk 中包含classLoader
            Class<?> loadClass = classLoader.loadClass("android.app.LoadedApk");
            Field mClassLoader = loadClass.getDeclaredField("mClassLoader");
            mClassLoader.setAccessible(true);

            // 将原来的ClassLoader替换为自定义ClassLoader
            mClassLoader.set(loadApkClassLoader, classLoader);

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }

    /**
     * 动态加载四大组件会报错，需要手动校正classloader。需要了解App的启动过程
     * <p>
     * 方式一：将当前加载类的classLoader替换PathClassLoder为自定义DexClassLoader
     * 方式二：在BootClassLoader 与PathClassLoader之间插入 自定义DexClassLoader
     * <p>
     * 方式一：该DexClassLoader一方面加载了源程序、另一方面以原mClassLoader为父节点，这就保证了即加载了源程序又没有放弃原先加载的资源与系统代码
     */
    private void loadActivityFirstByReplace(String dexPath) {
        String optPath = getDir("dex_opt", 0).getAbsolutePath();
        String libPath = getDir("dex_lib", 0).getAbsolutePath();

        DexClassLoader loader = new DexClassLoader(dexPath, optPath, libPath, getClassLoader());

        replaceClassLoader(loader);
        try {
            /**
             * 显示加载类。通过反射调用方法
             */
            Class<?> loadClass = loader.loadClass("com.qinglianyun.loaddex.MainActivity");

            if (null != loadClass) {

                /**
                 * 启动Activity会报错，说明能够加载Activity，只是不能执行。
                 * 因为Activity属于系统组件，有自己的生命周期，有系统的回调控制。
                 */
                Intent intent = new Intent(this, loadClass);
                startActivity(intent);  // 因为dex中不包含资源文件，所以启动后没有界面显示
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /**
     * 方式二：在BootClassLoader 与PathClassLoader之间插入 自定义DexClassLoader.
     * <p>
     * 主要是打破双亲委托机制,在BootClassLoader与PathClassLoader之前插入自定义DexClassLoader, 从自定义DexClassLoader中查找Activity.
     *
     * @param dexPath
     */
    private void loadActivitySecondByInsert(String dexPath) {
        String optPath = getDir("dex_opt", 0).getAbsolutePath();
        String libPath = getDir("dex_lib", 0).getAbsolutePath();


        ClassLoader pathClassLoader = MainActivity.class.getClassLoader();
        ClassLoader bootClassLoader = pathClassLoader.getParent();
        DexClassLoader loader = new DexClassLoader(dexPath, optPath, libPath, bootClassLoader);

        try {
            Field field = ClassLoader.class.getDeclaredField("parent");
            field.setAccessible(true);
            field.set(pathClassLoader, loader);

        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        try {
            /**
             * 显示加载类。通过反射调用方法
             */
            Class<?> loadClass = loader.loadClass("com.qinglianyun.loaddex.MainActivity");

            if (null != loadClass) {

                /**
                 * 启动Activity会报错，说明能够加载Activity，只是不能执行。
                 * 因为Activity属于系统组件，有自己的生命周期，有系统的回调控制。
                 */
                Intent intent = new Intent(this, loadClass);
                startActivity(intent);
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
//            md5.digest()

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * 方式三：合并dexElement，将父类PathClassloader与自定义的DexClassloader 中的数组进行合并
     */
    private void loadActivityThrByCombind() {

    }

    private void checkPermission() {
        List<String> list = new ArrayList<>();
        int permission = ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE);
        if (permission != PackageManager.PERMISSION_GRANTED) {
            list.add(Manifest.permission.WRITE_EXTERNAL_STORAGE);
        }

        int readPermission = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE);
        if (readPermission != PackageManager.PERMISSION_GRANTED) {
            list.add(Manifest.permission.READ_EXTERNAL_STORAGE);
        }
        if (!list.isEmpty()) {
            String[] text = new String[list.size()];
            for (int i = 0; i < list.size(); i++) {
                text[i] = list.get(i);
            }
            ActivityCompat.requestPermissions(this, text, 0x219);
        }
    }
}
