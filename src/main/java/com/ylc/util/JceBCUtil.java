package com.ylc.util;

import com.ylc.exception.JceException;
import com.ylc.jce.JceCipherObject;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: tree
 * @version: 1.0
 * date: 2017/8/21 12:10
 * @description: 用于TrustAFIS系统的加解密模块  适用于非加密机环境
 * own: Aratek
 */
public class JceBCUtil extends JceCipherObject {

    private static final Logger logger = LoggerFactory.getLogger(JceBCUtil.class);

    //初始化密钥存储区
    public static Map<String, String> KEY_STORE_AREA = new HashMap<String, String>();

    public JceBCUtil(){
        logger.debug("[use non-enc-device]");
        //加解密算法提供者,此处默认为加密算法提供商代码，此为Bouncycastle的代码
        super.algRule = "BC";
        Security.addProvider(new BouncyCastleProvider());
        //存储1号索引位的AES密钥
        KEY_STORE_AREA.put("AES_INDEX_1", "TVXnwzWem3ULpTb9d9veIUTQ0xRs+r3UfnWozmyZyWw=");
        //存储1号索引位的SM4密钥
        KEY_STORE_AREA.put("SM4_INDEX_1", "97d36yhP6Wl1Prz5ZYFR+GhaoXULKKQLMoPOajWYhYA=");
        //存储1号索引位的RSA公钥
        KEY_STORE_AREA.put("RSA_INDEX_1_PUB", "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwIJ2Sk4uS6uA2X8Q/A0etdIvpF8q3Xf+yqSDvfq17ZlSxhNitXlCEGOqAUbnTpn0mBHF7jAZKfQQd+BdSjhKPzqBoIFNXqzyhQ+K6mOrUUl4YpyNdKxvSJnvK0jOX9reoRxiMLCjfxwv+viOvF35Ohm7M1lt+Rk3cACLXwSwfzwIDAQAB");
        //存储1号索引位的RSA私钥
        KEY_STORE_AREA.put("RSA_INDEX_1_PRI", "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALAgnZKTi5Lq4DZfxD8DR610i+kXyrdd/7KpIO9+rXtmVLGE2K1eUIQY6oBRudOmfSYEcXuMBkp9BB34F1KOEo/OoGggU1erPKFD4rqY6tRSXhinI10rG9Ime8rSM5f2t6hHGIwsKN/HC/6+I68Xfk6GbszWW35GTdwAItfBLB/PAgMBAAECgYARnGFFG720Bgo/RZog1toe7O1kdD2P0jVUDvc9G0SLdzL2wRrNUwXn/3nLNODI2fffikgym1CxuAhmWr0yQwR18/sMiKydINir0XQgO3YQbP3OBxipfAmoTUbA2qIyN8VN2PS8bznYlW8CtTV/KB1sM4Sb8x5tgtdMiRDGnJFQsQJBAOsUVZT5sdquoto8xmZZtW5LB4BEiH12TEiWevcWM6cc5DukJO7Zp3Ohojg9dWUmyEIb0bhj+ISwfrchmqvkBVcCQQC/zTbs+HWC0i1dgDp0V7Ks+3hoR3dSdfdbN7J7jqZzfGMmlTQafZlQ5Fv3sNjJ9EjHefNagSquytKWG+7wA/ZJAkAPqhA12BmY19A0OJ6DzXCAg/FhA7AQpCRbJePVuR4CAbPXoY1weQJmexvDIZ1D+zyW4yGrZsX1mYkoDM4wrAYLAkA+7xcWqm/kfRJlm62SfzQhjmHz1X9Rj2OaiqwF3si/HBFsl4iBKLUl1chXfa+klINM8Lbo+3kF4Yc3ufKszqABAkEAmyhXBk1yFN4uGuPipKL7mCZz4+s/hwPUa2eaxncEnt1Sh+HSNoKbHslii/36D3QTO2K/zeCNdBIVTffoHi+n6g==");
        //存储1号索引位的SM2公钥
        KEY_STORE_AREA.put("SM2_INDEX_1_PUB", "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAETuSQynzV4LiOH0XClF03pzNdbzjxW/BpmW4u7yBrE2tuKcGuFfYRSioW+aiH2Qxq5Y73aT7fr9EhPIRA1yBejw==");
        //存储1号索引位的SM2私钥
        KEY_STORE_AREA.put("SM2_INDEX_1_PRI", "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQIgFUpdUcvdCLa7/1Kuf47OUWC/XDRCMTKbHuxdnlkgUMihRANCAARO5JDKfNXguI4fRcKUXTenM11vOPFb8GmZbi7vIGsTa24pwa4V9hFKKhb5qIfZDGrljvdpPt+v0SE8hEDXIF6P");

        //需要替换导出加密的RSA公钥Base64格式
//      COM_ENC_PUB_KEY=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUPjQrtdVS16cFTSpTfTaqy6lVKPEy9NBelZumeu2TID0fGwbR9CPPIqstpjmm8IbofGZifx9OdRzkWePsWiKaqhh8BoVYzkHdWgJiYJUaXERsvaa/V3+6dMiT6padRz3d3LiDdki+oa/hJiFgHF23DPgUOWnE2ZCPe552dT1vfwIDAQAB
        //对应的RSA私钥Base64格式
//      MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJQ+NCu11VLXpwVNKlN9NqrLqVUo8TL00F6Vm6Z67ZMgPR8bBtH0I88iqy2mOabwhuh8ZmJ/H051HORZ4+xaIpqqGHwGhVjOQd1aAmJglRpcRGy9pr9Xf7p0yJPqlp1HPd3cuIN2SL6hr+EmIWAcXbcM+BQ5acTZkI97nnZ1PW9/AgMBAAECgYAN3wWEst6uLML9H6upOkXblMkDJfHugbKJrILEViuqy6Z3JaaYDg8tD6JoLW38Qp9tBk7nl9uMZ4WiPGMJDPoVza/f0CuS8qHlhClNn/SMMe2lq4icJ0CQrV6NZeyW4B08B83CuJT2lTtZyTmoyxZneMTowpaSuNNSYr2JmX25SQJBAMTVIhRnpW7O7JKno3gled1BfE47QJYP4FF/V66gNpci2bnEkYSiU1G43Fhmzx5g56wbd7v6Xdan444dJv6tBDsCQQDAzfRuhEP43y56D/zZHzteG704JoeuW1uYP6S35I5fcqKE3qkcXo27D1eMQKdPF3ZeaSJD02YXGSE7MpA5S6GNAkEAjgPNK/XAOdvYetOzMTuw2n+mJXfA2MSpr4N2iwsTeCZv+wWljJHmFb+QU8QRyjRW0ymaUSmKTRcjKuVDvlqtAwJALI+tXdmuCBg1GrsVOm1wgDizDAZDt7Wfvtl+zY3CpibNjx4TQd5MrZ5HIsBSqwIGNp3f8IMshkwllRQDp2pmhQJAGL9azv6iJSqic6DCNi7sKii4LGyx4iAXw0fl/7y/WuSjZwaO5NCIWKgms8Ri8emIlPhEHuFIUWqLE6SihCX5CA==

    }

    /**
     * 根据算法和密钥索引从加密机上获取密钥对
     *
     * @param alg       算法
     * @param keyNum    密钥索引：1~100，  -1表示使用加密机外部密钥
     * @param keyLength 密钥位数：1024,2048,256
     * @return KeyPair 密钥对
     */
    public  KeyPair getKeyPair(String alg, int keyNum, int keyLength) throws JceException {
        logger.trace("------------获取密钥对开始-------------------------------");
        logger.trace("算法: " + alg);
        logger.trace("密钥的索引位: " + keyNum);
        logger.trace("密钥长度: " + keyLength);
        //声明密钥对变量
        KeyPair keyPair = null;
        //声明此方法涉及的密钥类型：1表示公钥，2表示私钥，3表示秘钥
        int pubKeyType = 1;
        int priKeyType = 2;
        try {
            if (-1 != keyNum) {
                // 初始化密钥对生成器,指定内部密钥的密钥序号
                //生成公钥
                PublicKey publicKey = (PublicKey) changeByteToKey(alg, KEY_STORE_AREA.get(JceCommonUtil.getKeyIndex(alg, keyNum, pubKeyType)), pubKeyType);
                //生成私钥
                PrivateKey privateKey = (PrivateKey) changeByteToKey(alg, KEY_STORE_AREA.get(JceCommonUtil.getKeyIndex(alg, keyNum, priKeyType)), priKeyType);
                keyPair = new KeyPair(publicKey, privateKey);
            } else {
                // 获取密钥对的密钥生成器
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, algRule);
                // 初始化密钥对生成器,指定内部密钥的密钥序号
                kpg.initialize(keyLength);
                // 获取内部密钥对
                keyPair = kpg.genKeyPair();
            }
            //调试信息
            logger.trace("密钥公钥格式：" + keyPair.getPublic().getFormat());
            logger.trace("密钥私钥格式：" + keyPair.getPrivate().getFormat());
            logger.trace("密钥公钥Base64串：" + Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
            logger.trace("密钥私钥Base64串：" + Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new JceException("指定的运算算法 " + alg + " 不存在，" + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new JceException("指定的运算算法提供者不存在，" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new JceException("随机生成/获取密钥区 密钥对失败，" + e.getMessage());
        }
        logger.trace("------------获取密钥对结束-------------------------------");
        return keyPair;
    }

    /**
     * 根据算法和密钥索引从加密机上获取密钥
     *
     * @param alg       算法
     * @param keyNum    密钥索引：1~100，  -1表示使用加密机外部密钥
     * @param keyLength 密钥位数：1024,2048,256
     * @return Key 成功：密钥 ，失败： null
     * @throws JceException
     */
    public  Key getKey(String alg, int keyNum, int keyLength) throws JceException {
        logger.trace("------------获取密钥开始-------------------------------");
        logger.trace("算法: " + alg);
        logger.trace("密钥的索引位: " + keyNum);
        logger.trace("密钥长度: " + keyLength);
        //声明密钥变量
        Key keyTemp = null;
        //声明此方法涉及的密钥类型：1表示公钥，2表示私钥，3表示秘钥
        int keyType = 3;
        try {
            if (-1 != keyNum) {
                // 从内部配置中检索指定索引位的Base64格式的密钥串
                String keyValue = KEY_STORE_AREA.get(JceCommonUtil.getKeyIndex(alg, keyNum, keyType));
                // 将Base64格式的密钥串转换为需要的密钥格式
                keyTemp = changeByteToKey(alg, keyValue, keyType);
            } else {
                // 获取密钥的密钥生成器
                KeyGenerator kg = KeyGenerator.getInstance(alg, algRule);
                // 初始化密钥对生成器,指定内部密钥的密钥序号
                kg.init(keyLength);
                keyTemp = kg.generateKey();
            }
            //调试信息
            logger.trace("生成密钥算法：" + keyTemp.getAlgorithm());
            logger.trace("密钥格式：" + keyTemp.getFormat());
            logger.trace("密钥Base64串：" + Base64.encodeBase64String(keyTemp.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new JceException("指定的运算算法 " + alg + " 不存在，" + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new JceException("指定的运算算法提供者不存在，" + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            throw new JceException("随机生成/获取密钥区 密钥失败，" + e.getMessage());
        }
        logger.trace("------------获取密钥对结束-------------------------------");
        // 获取内部密钥
        return keyTemp;
    }
}
