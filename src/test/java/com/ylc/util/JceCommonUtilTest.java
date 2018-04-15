package com.ylc.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * author: tree
 * version: 1.0
 * since:
 * date: 2018/4/15 16:32
 * description:
 * own:
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