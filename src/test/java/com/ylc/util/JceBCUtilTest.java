package com.ylc.util;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * 文件名：
 * 作者：tree
 * 时间：2017/4/1
 * 描述：
 * 版权：亚略特
 */
public class JceBCUtilTest {

    JceBCUtil jce = null;

    @Before
    public void setUp() throws Exception {
        jce = new JceBCUtil();
    }

    @Test
    public void testGetKeyPair() throws Exception {
        assertNotNull(jce.getKeyPair("RSA",-1,1024));
        assertNotNull(jce.getKeyPair("SM2",1,0));
    }

    @Test
    public void testGetKey() throws Exception {
        assertNotNull(jce.getKey("AES",-1,128));
        assertNotNull(jce.getKey("SM4",-1,256));
    }
}