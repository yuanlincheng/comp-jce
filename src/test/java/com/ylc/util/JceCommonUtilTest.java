package com.ylc.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * 文件名：
 * 作者：tree
 * 时间：2017/4/10
 * 描述：
 * 版权：亚略特
 */
public class JceCommonUtilTest {

    @Test
    public void testReadCertFile() throws Exception {
        String path = "D://MFACA.cer";
        assertNotNull(JceCommonUtil.readCertFile(path));
    }

    @Test
    public void testChangeAlgAble() throws Exception {
        assertEquals("RSA", JceCommonUtil.changeAlgAble("SM2"));
        assertEquals("SM4", JceCommonUtil.changeAlgAble("SM4"));
    }

    @Test
    public void testGetKeyIndex() throws Exception {
        assertEquals("AES_INDEX_1", JceCommonUtil.getKeyIndex("AES", 1, 3));
        assertEquals("RSA_INDEX_1_PUB", JceCommonUtil.getKeyIndex("RSA", 1, 1));
        assertEquals("RSA_INDEX_1_PRI", JceCommonUtil.getKeyIndex("RSA", 1, 2));
        assertEquals("SM2_INDEX_1_PRI", JceCommonUtil.getKeyIndex("SM2", 1, 2));
    }

    @Test
    public void testChangeTransAble() throws Exception {
        assertEquals("RSA/ECB/PKCS1Padding", JceCommonUtil.changeTransAble("SM2"));
        assertEquals("AES/ECB/PKCS5PADDING", JceCommonUtil.changeTransAble("AES/ECB/PKCS5PADDING"));
    }

    @Test
    public void testChangeSM2PriKey() throws Exception {
        String keyStr = "QAAUJIMCFCBCiAJKEBSAAAIcAAmDWCGsgACgExEAqFk=";
        assertNotNull(JceCommonUtil.changeSM2PriKey(keyStr));
    }
}