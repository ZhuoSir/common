package com.chen.utils;

import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtils {

    /**
     * 检查字符串是否为null或者空
     *
     * */
    public static boolean isNotNullOrEmpty(final String str) {
        return null != str && !"".equals(str);
    }

    /**
     * 检查字符串是否为null或者空
     *
     * */
    public static boolean isNullOrEmpty(final String str) {
        return !isNotNullOrEmpty(str);
    }


    /**
     * 检查字符串是否包含
     *
     * */
    public static boolean contains(final CharSequence sequence, final CharSequence searchSequence) {
        if (null == sequence || null == searchSequence) {
            return false;
        }

        return sequence.toString().indexOf(searchSequence.toString(), 0) > -1;
    }


    /**
     * 颠倒字符串
     * */
    public static String reverse(final String str) {
        char[] chars = str.toCharArray();
        for (int i = 0, j = chars.length-1; i < j; i++, j--) {
            char t = chars[i];
            chars[i] = chars[j];
            chars[j] = t;
        }

        return new String(chars);
    }


    /**
     * 判断字符串是不是数字
     *
     * */
    public static boolean isNumberic(final CharSequence str) {
        Pattern pattern = Pattern.compile("^[-+]?(([0-9]+)([.]([0-9]+))?|([.]([0-9]+))?)$");
        Matcher isNum   = pattern.matcher(str);
        return isNum.matches();
    }


    /**
     * 判断字符串是不是中文
     *
     * */
    public static boolean isChinese(final CharSequence str) {
        Pattern pattern = Pattern.compile("^[\\u4e00-\\u9fa5]*$");
        Matcher isCh    = pattern.matcher(str);
        return isCh.matches();
    }


    /**
     * MD5加密
     *
     * @param str 加密字符串
     * @return 加密结果
     */
    public static String EncodeByMD5(final CharSequence str) {
        MessageDigest md5;
        md5 = null;

        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        BASE64Encoder base64Encoder = new BASE64Encoder();
        String newStr = null;
        try {
            newStr = base64Encoder.encode(md5.digest(str.toString().getBytes("utf-8")));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return newStr;
    }


    /**
     * 检测email是否符合格式
     *
     * */
    public static boolean checkEmail(String email) {
        Pattern pattern = Pattern.compile("^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+");
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }


    /**
     * 检测手机号是否符合格式
     *
     * */
    public static boolean checkPhoneNumber(String phoneNumber) {
        Pattern pattern = Pattern.compile("^1[3|4|5|7|8][0-9]{9}$");
        Matcher matcher = pattern.matcher(phoneNumber);
        return matcher.matches();
    }


    /**
     * sha256_HMAC加密
     * @param message 消息
     * @param secret  秘钥
     * @return 加密后字符串
     */
    public static String sha256_HMAC(String message, String secret) {
        String hash = "";
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            byte[] bytes = sha256_HMAC.doFinal(message.getBytes());
            hash = byteArrayToHexString(bytes);
            System.out.println(hash);
        } catch (Exception e) {
            System.out.println("Error HmacSHA256 ===========" + e.getMessage());
        }
        return hash;
    }


    /**
     * 将加密后的字节数组转换成字符串
     *
     * @param b 字节数组
     * @return 字符串
     */
    public static String byteArrayToHexString(byte[] b) {
        StringBuilder hs = new StringBuilder();
        String stmp;
        for (int n = 0; b!=null && n < b.length; n++) {
            stmp = Integer.toHexString(b[n] & 0XFF);
            if (stmp.length() == 1)
                hs.append('0');
            hs.append(stmp);
        }
        return hs.toString().toLowerCase();
    }
}
