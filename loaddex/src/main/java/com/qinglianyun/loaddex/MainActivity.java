package com.qinglianyun.loaddex;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {
    public static final String TAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String fingerprint = Build.FINGERPRINT;

        Log.d(TAG, "onCreate() called with: 动态加载\n fingerprint = "+fingerprint);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    digest();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public static String bytesToHexString(byte[] src, int length) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString().toUpperCase();
    }

    private void digest() throws Exception {
//        String encode = "4143cb60bf8083ac94c57418a9a7ff5a14a63feade6b46d9d0af3182ccbdf7af";
        String encode = "57fdeca2cac0509b2e9e5c52a5b573c1608a33ac1ffb9e8210d2e129557e7f1b";
        byte[] encodeBytes = encode.getBytes();

//        String ppp = "45678REAL";
        String ppp = "87654REAL";

        Log.e("测试", "原字符串十六进制 =" + bytesToHexString(ppp.getBytes(),ppp.getBytes().length));

        MessageDigest md5 = MessageDigest.getInstance("Md5");
        byte[] digest = md5.digest(ppp.getBytes());


        String key = "goodl-aes-key124";

        byte[] encodeStr = aesEncrypt(ppp.getBytes(), key.getBytes());

        Log.e("测试", " encode = " + bytesToHexString(encodeStr, encodeStr.length) + "\ndigest =" + bytesToHexString(digest, digest.length) + " length = " + digest.length);
//        Log.e("测试", "deeencode =" +Arrays.toString(encodeBytes));

        boolean equals = Arrays.equals(encodeBytes, digest);
        if (equals) {
            Log.e("测试", "result =" + equals);
        }


    }

    /**
     * AES加密
     *
     * @param content    待加密的内容
     * @param encryptKey 加密密钥
     * @return 加密后的byte[]
     * @throws Exception
     */
    public static byte[] aesEncrypt(byte[] content, byte[] encryptKey) throws Exception {
        SecretKeySpec sKeySpec = new SecretKeySpec(encryptKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String ivStr = "goodl-aes-iv1235";
        IvParameterSpec iv = new IvParameterSpec(ivStr.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, iv);
        return cipher.doFinal(content);
    }

    /**
     * AES解密
     *
     * @param encryptBytes 待解密的byte[]
     * @param decryptKey   解密密钥
     * @return 解密后的String
     * @throws Exception
     */
    public static byte[] aesDecryptByBytes(byte[] encryptBytes, byte[] decryptKey) throws Exception {

        SecretKeySpec sKeySpec = new SecretKeySpec(decryptKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(decryptKey);
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec, iv);
        return cipher.doFinal(encryptBytes);
    }

}
