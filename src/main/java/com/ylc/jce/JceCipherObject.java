package com.ylc.jce;

import com.ylc.exception.JceException;
import com.ylc.util.JceCommonUtil;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * author: tree
 * version: 1.0
 * since:
 * date: 2018/4/15 16:32
 * description:
 * own:
 */
public abstract class JceCipherObject {

    private static Logger logger = LoggerFactory.getLogger(JceCipherObject.class);

    //加解密算法提供者,此处默认为加密算法提供商代码
    protected String algRule = "";

    //子证书，用于缓存
    Certificate subCert = null;

    /**
     * 根据算法，模式,明文，密钥索引以及密钥类型对数据进行加密
     * @param alg         算法 ： RSA,AES,SM4,SM2
     * @param trans       模式：RSA/ECB/PKCS1Padding,AES/ECB/PKCS5PADDING
     * @param plain       明文数据 二进制类型
     * @param keyNum      密钥索引：1~100,-1表示使用外部密钥  -2表示指定密钥
     * @param keyType     密钥类型：1表示公钥，2表示私钥，3表示秘钥
     * @param keyLength   密钥位数：1024,2048,128   若keyNum != -1,则固定值为-1
     * @param externalKey 外部密钥，Base64编码串,若keyNum != -2,则固定值为null
     * @return String  成功 : Base64编码密文数据  失败： null
     */
    public String encrypt(String alg, String trans, byte[] plain, int keyNum, int keyType, int keyLength, String externalKey) throws JceException{
        //此处调试输出
        logger.debug("------------加密数据开始-------------------------------");
        logger.debug("算法: " + alg);
        logger.debug("模式: " + trans);
        logger.debug("索引: " + keyNum);
        logger.debug("明文长度: " + plain.length);
        logger.debug("类型: " + keyType);
        if(algRule.equals("BC")){
            //转换成可用的算法
            alg = JceCommonUtil.changeAlgAble(alg);
            trans = JceCommonUtil.changeTransAble(trans);
        }
        //根据算法和索引获取密钥
        Key key;
        Cipher cipher;
        try {
            if (-2 != keyNum) {
                if ("RSA".equals(alg) || "SM2".equals(alg)) {
                    //获取密钥对
                    KeyPair kp = getKeyPair(alg, keyNum, keyLength);
                    logger.debug("获取密钥对成功");
                    //判定当前获取公钥还是私钥
                    if (1 == keyType) {
                        //获取公钥
                        key = kp.getPublic();
                    } else {
                        //获取私钥
                        key = kp.getPrivate();
                    }
                } else {
                    //获取密钥
                    key = getKey(alg, keyNum, keyLength);
                    logger.debug("获取密钥成功");
                }
                //判定Key是否生成成功
                if (null == key) {
                    throw new JceException("密钥对或密钥 生成失败，请检查索引位置是否存在密钥对或密钥");
                }
            } else {
                //生成密钥
                key = changeByteToKey(alg, externalKey, keyType);
                logger.debug("生成密钥成功");
            }
            //获取加解密对象
            cipher = Cipher.getInstance(trans, algRule);
            // 初始化Cipher对象(加密模式)
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // 调用加密函数
            byte[] tResult = cipher.doFinal(plain);
            // 判定是否加密成功
            if (tResult == null) {
                throw new JceException(trans + " 模式，加密出错");
            }
            logger.debug("加密数据，加密后内容长度为: " + Base64.encodeBase64String(tResult).length());
            logger.trace("加密数据，加密后内容为: " + Base64.encodeBase64String(tResult));
            //返回加密数据
            logger.debug("------------加密数据结束-------------------------------");
            return Base64.encodeBase64String(tResult);
        } catch (NoSuchAlgorithmException e) {
            throw new JceException("指定的运算算法 " + alg + " 不存在，" + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new JceException("指定的运算算法提供者不存在，" + e.getMessage());
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new JceException("指定的运算算法模式 " + trans + " 不正确，" + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new JceException("指定加密的数据 " + alg + " 非法，" + e.getMessage());
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new JceException("指定的运算算法模式 " + trans + " 不存在，" + e.getMessage());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new JceException("指定的运算密钥 " + alg + " 非法，" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new JceException("加密失败，" + e.getMessage());
        }
    }

    /**
     * 根据算法，模式,Base64密文串，密钥索引以及密钥类型对数据进行解密
     * @param alg         算法 ： RSA,AES,SM4,SM2
     * @param trans       模式：RSA/ECB/PKCS1Padding,AES/ECB/PKCS5PADDING,
     * @param plain       Base64密文串
     * @param keyNum      密钥索引：1~100,-1表示使用外部密钥  -2表示指定密钥
     * @param keyType     密钥类型：1表示公钥，2表示私钥，3表示秘钥
     * @param externalKey 外部密钥，Base64编码串,若keyNum != -2,则固定值为null
     * @param resultType  返回数据编码类型， 1表示String  2表示Base64串
     * @return String  成功 : 明文数据  失败： null
     */
    public String decrypt(String alg, String trans, String plain, int keyNum, int keyType, String externalKey, int resultType) throws JceException{
        // 此处调试输出
        logger.debug("------------解密数据开始-------------------------------");
        logger.debug("算法: " + alg);
        logger.debug("模式: " + trans);
        logger.debug("索引: " + keyNum);
        logger.debug("Base64密文串: " + plain.length());
        logger.debug("类型: " + keyType);
        if(algRule.equals("BC")){
            //转换成可用的算法
            alg = JceCommonUtil.changeAlgAble(alg);
            trans = JceCommonUtil.changeTransAble(trans);
        }
        // 根据算法和索引获取密钥
        Key key;
        String result;
        Cipher cipher;
        try {
            if (-2 != keyNum) {
                if ("RSA".equals(alg) || "SM2".equals(alg)) {
                    // 获取RSA密钥对,-1为固定值,无意义
                    KeyPair kp = getKeyPair(alg, keyNum, -1);
                    logger.debug("获取密钥对成功");
                    // 判定当前获取公钥还是私钥
                    if (1 == keyType) {
                        // 获取公钥
                        key = kp.getPublic();
                    } else {
                        // 获取私钥
                        key = kp.getPrivate();
                    }
                } else {
                    // 获取密钥,-1为固定值,无意义
                    key = getKey(alg, keyNum, -1);
                    logger.debug("获取密钥成功");
                }
                // 判定Key是否生成成功
                if (null == key) {
                    throw new JceException("密钥对或密钥 生成失败，请检查索引位置是否存在密钥对或密钥");
                }
            } else {
                //生成密钥
                key = changeByteToKey(alg, externalKey, keyType);
                logger.debug("生成密钥成功");
            }

            // Base64编码密文串解码成二进制密文数据
            byte[] plainByte = Base64.decodeBase64(plain);

            // 获取加解密对象
            cipher = Cipher.getInstance(trans, algRule);
            // 初始化Cipher对象(解密模式)
//          cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec("UISwD9fW6cFh9SNS".getBytes()));
            cipher.init(Cipher.DECRYPT_MODE, key);
            // 调用加密函数
            byte[] tResult = cipher.doFinal(plainByte);
            // 判定是否加密成功
            if (tResult == null) {
                throw new JceException(trans + " 模式，加密出错");
            }
            // 返回加密数据
            if (1 == resultType) {
                result = new String(tResult, StandardCharsets.UTF_8);
            } else {
                result = Base64.encodeBase64String(tResult);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new JceException("指定的运算算法 " + alg + " 不存在，" + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new JceException("指定的运算算法提供者不存在，" + e.getMessage());
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new JceException("指定的运算算法模式 " + trans + " 不正确，" + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new JceException("指定解密的密文数据 " + alg + " 非法，" + e.getMessage());
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new JceException("指定的运算算法模式 " + trans + " 不存在，" + e.getMessage());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new JceException("指定的运算密钥 " + alg + " 非法，" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new JceException("解密失败，" + e.getMessage());
        }
        logger.debug("解密数据，解密后内容长度为: " + result.length());
        logger.trace("解密数据，解密后内容为: " + result);
        logger.debug("------------解密数据结束-------------------------------");
        return result;
    }

    /**
     * 根据key对应的算法，签名算法,明文数据,密钥索引，密钥长度以及Base64编码串 对数据进行签名
     *
     * @param keyAlg      生成key对应的算法 ： RSA,AES
     * @param signAlg     签名算法 ： SHA1WithRSA,SHA224WithRSA...
     * @param plain       明文数据
     * @param keyNum      密钥索引：1~100,-1表示使用外部密钥  -2表示指定密钥
     * @param keyLength   密钥位数：1024,2048,若keyNum != -1,则固定值为-1
     * @param externalKey 外部密钥，Base64编码串,若keyNum != -2,则固定值为null
     * @return String  成功 : Base64编码签名数据  失败： null
     */
    public String sign(String keyAlg, String signAlg, String plain, int keyNum, int keyLength, String externalKey) throws JceException{
        // 此处调试输出
        logger.debug("------------签名流程开始-------------------------------");
        logger.debug("key对应算法: " + keyAlg);
        logger.debug("签名算法: " + signAlg);
        logger.debug("明文数据: " + plain.length());
        logger.debug("索引: " + keyNum);

        if(algRule.equals("BC")){
            //转换成可用的算法
            keyAlg = JceCommonUtil.changeAlgAble(keyAlg);
        }

        // 根据算法和索引获取公钥
        PrivateKey key;
        // 定义签名对象
        Signature signatue;
        //存放Base64编码签名数据
        byte[] out;
        try {
            if (-2 != keyNum) {
                // 获取私钥,-1为默认,无意义
//                key = (PrivateKey)getKey(keyAlg,keyNum,-1,2);
                // 获取RSA密钥对
                KeyPair kp = getKeyPair(keyAlg, keyNum, keyLength);
                // 获取公钥
                key = kp.getPrivate();
                // 判定Key是否生成成功
                if (null == key) {
                    throw new JceException("密钥对 生成失败，请检查索引位置是否存在密钥对或密钥");
                }
            } else {
                //生成私钥
                key = (PrivateKey) changeByteToKey(keyAlg, externalKey, 2);
            }

            // 获取签名对象
            signatue = Signature.getInstance(signAlg, algRule);
            // 初始化签名对象(私钥)
            signatue.initSign(key);
            // 更新要验签的数据
            signatue.update(plain.getBytes(StandardCharsets.UTF_8));
            //进行签名运算
            out = signatue.sign();

            logger.debug("签名数据: " + Base64.encodeBase64String(out).length());
            logger.debug("------------签名流程结束-------------------------------");
            return Base64.encodeBase64String(out);
        } catch (NoSuchAlgorithmException e) {
            throw new JceException("指定的运算算法 " + signAlg + " 不存在，" + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new JceException("指定的运算算法提供者不存在，" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new JceException("签名失败，" + e.getMessage());
        }
    }

    /**
     * 根据key对应的算法，签名算法,明文数据,Base64签名串以及密钥索引对数据进行验签
     *
     * @param keyAlg      生成key对应的算法 ： RSA,AES
     * @param alg         签名算法 ： SHA1WithRSA,SHA224WithRSA...
     * @param plain       明文数据
     * @param signData    Base64签名串
     * @param keyNum      密钥索引：1~100,-1表示使用外部密钥  -2表示指定密钥
     * @param externalKey 公钥数据(Base64编码串),若keyNum != -2,则固定值为null
     * @return boolean  成功 : true  失败： false
     */
    public boolean verifySign(String keyAlg, String alg, String plain, String signData, int keyNum, String externalKey) throws JceException{
        // 此处调试输出
        logger.debug("------------验签流程开始-------------------------------");
        logger.debug("key对应算法: " + keyAlg);
        logger.debug("签名算法: " + alg);
        logger.debug("明文数据: " + plain.length());
        logger.debug("索引: " + keyNum);
        logger.debug("Base64签名串: " + signData);
        logger.debug("传入的签名公钥串: " + externalKey);
        //如果算法提供商是BC
        if(algRule.equals("BC")){
            //转换成可用的算法
            keyAlg = JceCommonUtil.changeAlgAble(keyAlg);
        }
        //根据算法和索引获取公钥
        PublicKey key;
        //定义签名对象
        Signature signatue;
        boolean flag;
        try {
            if (-2 != keyNum) {
                // 获取RSA密钥对,-1为默认,无意义
                KeyPair kp = getKeyPair(keyAlg, keyNum, -1);
                // 获取公钥
                key = kp.getPublic();
                // 判定Key是否生成成功
                if (null == key) {
                    throw new JceException("密钥对 生成失败，请检查索引位置是否存在密钥对或密钥");
                }
            } else {
                //生成公钥
                key = (PublicKey) changeByteToKey(keyAlg, externalKey, 1);
            }
            // Base64编码签名串解码成二进制签名数据
            byte[] signDataByte = Base64.decodeBase64(signData);
            //获取签名对象
            signatue = Signature.getInstance(alg, algRule);
            //初始化验签对象(公钥)
            signatue.initVerify(key);
            //更新要验签的数据
            signatue.update(plain.getBytes(StandardCharsets.UTF_8));
            //进行验签运算
            flag = signatue.verify(signDataByte);
        } catch (NoSuchAlgorithmException e) {
            throw new JceException("指定的运算算法 " + alg + " 不存在，" + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new JceException("指定的运算算法提供者不存在，" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new JceException("验签失败，" + e.getMessage());
        }
        logger.debug("------------验签流程结束-------------------------------");
        return flag;
    }

    /**
     * 根据根证书验证子证书的有效性
     *
     * @param certData     子证书数据串，Base64编码
     * @param rootFilePath 根证书在服务器上的绝对路径
     * @return boolean  成功 : true  失败： false
     */
    public boolean verifyCert(String certData, String rootFilePath){
        logger.debug("------------证书验证开始-------------------------------");
        logger.debug("证书数据: " + certData.length());
        logger.debug("根证书路径: " + rootFilePath);
        CertificateFactory cf;  //证书工厂类
        boolean flag = false;   //验证通过标志
        String start = "-----BEGIN CERTIFICATE-----\n";   //证书头
        String end = "\n-----END CERTIFICATE-----";       //证书尾
        String certificateValue = start + certData + end;  //完整证书串
        //读取根证书到输入流中  将证书串写进流
        try( FileInputStream rootIn = new FileInputStream(rootFilePath);ByteArrayInputStream subIn = new ByteArrayInputStream(certificateValue.getBytes("UTF-8"))){
            cf = CertificateFactory.getInstance("X.509");       //证书生成格式定义为X.509
            Certificate rootCert = cf.generateCertificate(rootIn);      //生成根证书对象
            setSubCert(cf.generateCertificate(subIn));      //生成用户证书对象
            logger.debug("根证书类型: " + rootCert.getType());
            logger.debug("子证书类型: " + subCert.getType());
            PublicKey rootPub = rootCert.getPublicKey();        //获取根证书中的公钥
            PublicKey subPub = subCert.getPublicKey();      //获取子证书中的公钥
            //输出子证书中的公钥
            logger.debug("子证书中的公钥串：" + Base64.encodeBase64String(subPub.getEncoded()));
            //用根证书的公钥验证子证书的有效性
            subCert.verify(rootPub);
            //验证通过标志
            flag = true;
        }  catch (Exception e) {
            e.printStackTrace();
            logger.debug("根据根证书验证子证书的有效性失败: " + e.getMessage());
        }
        logger.debug("------------证书验证结束-------------------------------");
        return flag;
    }

    /**
     * 根据算法，模式,密钥的Base64编码串以及密钥类型将密钥由byte转为key类型
     *
     * @param alg       算法 ： RSA,AES
     * @param keyBase64 ，密钥的Base64编码串
     * @param keyType   密钥类型：1表示公钥，2表示私钥，3表示秘钥
     * @return key  成功 : 密钥  失败： null
     */
    public  Key changeByteToKey(String alg, String keyBase64, int keyType) {
        //此处调试输出
        logger.debug("------------密钥类型转换开始-------------------------------");
        logger.debug("算法: " + alg);
        logger.debug("密钥的Base64编码串: " + keyBase64.length());
        logger.debug("密钥类型: " + keyType);

        //初始化密钥
        Key key = null;
        try {
            //对Base64编码密钥串数据进行Base64转码
            byte[] keyBytes = Base64.decodeBase64(keyBase64);
            logger.debug("密钥的长度:"+keyBytes.length);
            //判定算法
            if ("RSA".equals(alg) || "SM2".equals(alg)) {
                if (1 == keyType) {
                    //转成公钥
                    logger.debug("转换成公钥");
                    //初始化X.509密钥生成空间
                    X509EncodedKeySpec keySpec;
                    //当密钥为按openssl标准产生时
                    if (keyBytes.length == 140) {
                        //在密钥数据的前面加上22位的JCE密钥头
                        byte[] bX509PubKeyHeader = {48, -127, -97, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -127, -115, 0};
                        byte[] bPubKey = new byte[keyBytes.length + bX509PubKeyHeader.length];
                        System.arraycopy(bX509PubKeyHeader, 0, bPubKey, 0, bX509PubKeyHeader.length);
                        System.arraycopy(keyBytes, 0, bPubKey, bX509PubKeyHeader.length, keyBytes.length);
                        //生成密钥空间
                        keySpec = new X509EncodedKeySpec(bPubKey);
                    } else {
                        //当密钥为按JCE标准产生时
                        //生成密钥空间
                        keySpec = new X509EncodedKeySpec(keyBytes);
                    }
                    //生成公钥
                    KeyFactory keyFactory = KeyFactory.getInstance(alg);
                    key = keyFactory.generatePublic(keySpec);
                } else {
                    logger.debug("转换成私钥");
                    //转成私钥
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    //生成私钥
                    KeyFactory keyFactory = KeyFactory.getInstance(alg);
                    key = keyFactory.generatePrivate(keySpec);
                }
            } else {
                logger.debug("转换成密钥");
                //生成密钥
                key = new SecretKeySpec(keyBytes, alg);
            }
            logger.debug("此密钥的格式: " + key.getFormat());
            logger.debug("------------密钥类型转换结束-------------------------------");
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //返回密钥
        return key;
    }

    /**
     * 根据算法和密钥索引从密钥存储区上获取密钥对
     * @param alg       算法
     * @param keyNum    密钥索引：1~100，  -1表示使用外部密钥
     * @param keyLength 密钥位数：1024,2048,256
     * @return KeyPair 密钥对
     */
    public abstract KeyPair getKeyPair(String alg, int keyNum, int keyLength) throws JceException;

    /**
     * 根据算法和密钥索引从密钥存储区上获取密钥
     * @param alg       算法
     * @param keyNum    密钥索引：1~100，  -1表示使用外部密钥
     * @param keyLength 密钥位数：1024,2048,256
     * @return Key 成功：密钥 ，失败： null
     */
    public abstract Key getKey(String alg, int keyNum, int keyLength) throws JceException;

    public String getAlgRule() {
        return algRule;
    }

    public void setAlgRule(String algRule) {
        this.algRule = algRule;
    }

    public Certificate getSubCert() {
        return subCert;
    }

    public void setSubCert(Certificate subCert) {
        this.subCert = subCert;
    }
}
