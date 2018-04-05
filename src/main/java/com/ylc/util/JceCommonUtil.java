package com.ylc.util;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

/**
 * @author: tree
 * @version: 1.0
 * date: 2017/8/21 11:56
 * @description:
 * own: Aratek
 */
public class JceCommonUtil {
    /**
     * 读取证书文件中的公钥串
     * @param path 证书文件路径
     * @return 公钥的Base64密码串
     */
    public static String readCertFile(String path) {
        // 读取证书文件
        File file = new File(path);
        try(InputStream inStream = new FileInputStream(file)) {
            // 创建X509工厂类
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            //CertificateFactory cf = CertificateFactory.getInstance("X509");
            // 创建证书对象
            X509Certificate oCert = (X509Certificate) cf
                    .generateCertificate(inStream);
            inStream.close();
            SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd");
            String info = null;
            // 获得证书版本
            info = String.valueOf(oCert.getVersion());
            System.out.println("证书版本:" + info);
            // 获得证书序列号
            info = oCert.getSerialNumber().toString(16);
            System.out.println("证书序列号:" + info);
            // 获得证书有效期
            Date beforedate = oCert.getNotBefore();
            info = dateformat.format(beforedate);
            System.out.println("证书生效日期:" + info);
            Date afterdate = oCert.getNotAfter();
            info = dateformat.format(afterdate);
            System.out.println("证书失效日期:" + info);
            // 获得证书主体信息
            info = oCert.getSubjectDN().getName();
            System.out.println("证书拥有者:" + info);
            // 获得证书颁发者信息
            info = oCert.getIssuerDN().getName();
            System.out.println("证书颁发者:" + info);
            // 获得证书签名算法名称
            info = oCert.getSigAlgName();
            System.out.println("证书签名算法:" + info);

            // 获得公钥
            info = org.apache.commons.codec.binary.Base64.encodeBase64String(oCert.getPublicKey().getEncoded());
            System.out.println("证书公钥:" + info);

            return info;
        } catch (CertificateException e) {
            System.out.println("解析证书出错！");
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            System.out.println("未找到根证书文件！");
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("读取证书失败！");
            e.printStackTrace();
        }finally {

        }
        return null;
    }

    /**
     * 返回支持的算法种类,由于BC不支持SM2算法，只能做此转换
     * @param alg 算法
     * @return 可用算法
     */
    public static String changeAlgAble(String alg) {
        //将算法改为可用的算法
        switch (alg) {
            case "SM2":
                return "RSA";
            default:
                return alg;
        }
    }

    /**
     * 获取存储位置的索引字段
     * @param alg     算法
     * @param keyNum  密钥索引：1~100，  -1表示使用加密机外部密钥
     * @param keyType 密钥类型：1表示公钥，2表示私钥，3表示秘钥
     * @return 存储位置的索引字段
     */
    public static String getKeyIndex(String alg, int keyNum, int keyType) {
        //根据参数组装索引字段
        switch (keyType) {
            case 1:
                return (alg + "_" + "INDEX" + "_" + keyNum + "_PUB").toUpperCase();
            case 2:
                return (alg + "_" + "INDEX" + "_" + keyNum + "_PRI").toUpperCase();
            default:
                return (alg + "_" + "INDEX" + "_" + keyNum).toUpperCase();
        }
    }

    /**
     * 返回支持的算法模式 ,由于BC不支持SM2算法，只能做此转换
     * @param trans 算法模式
     * @return 可用算法模式
     */
    public static String changeTransAble(String trans) {
        //将算法模式改为可用的算法模式
        switch (trans) {
            case "SM2":
                return "RSA/ECB/PKCS1Padding";
            default:
                return trans;
        }
    }

    /**
     * 将 C的32位SM2私钥数据转换为java JCE标准的139位私钥数据
     * @param priKey C的32位SM2私钥数据 (Base64串)
     * @return java JCE标准的139位私钥数据 (Base64串)
     */
    public static String changeSM2PriKey(String priKey) {
        byte[] desByte = new byte[139];
        String keyStr1 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEJuqKOTAgjv2RMvccUQqrV0OLPbwn0wTnmOzK8qDqdOt1ANnP8w5jEBXHc3KOjCUJOAoi4edCtqugnc+FfELM6g==";
        byte[] header = {48,-127,-120,2,1,0,48,19,6,7,42,-122,72,-50,61,2,1,6,8,42,-127,28,-49,85,1,-126,45,4,110,48,108,2,1,1,2,33,0};
        byte[] header1 = {-95,68};
        byte[] key = Base64.getDecoder().decode(priKey);
        byte[] key1 = Base64.getDecoder().decode(keyStr1);
        System.arraycopy(header, 0, desByte, 0, header.length);
        System.arraycopy(key, 0, desByte,header.length, key.length);
        System.arraycopy(header1, 0, desByte,header.length + key.length, header1.length);
        System.arraycopy(key1, 23, desByte, header.length + key.length + 2, key1.length - 23);
        return Base64.getEncoder().encodeToString(desByte);
    }
}
