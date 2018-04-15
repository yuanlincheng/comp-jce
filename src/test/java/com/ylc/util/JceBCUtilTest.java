package com.ylc.util;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * author: tree
 * version: 1.0
 * since:
 * date: 2018/4/16 0:25
 * description:
 * own:
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
        assertNotNull(jce.getKeyPair("RSA",1,0));
    }

    @Test
    public void testGetKey() throws Exception {
        assertNotNull(jce.getKey("AES",-1,128));
        assertNotNull(jce.getKey("SM4",-1,128));
        assertNotNull(jce.getKey("SM4",1,0));
    }
}