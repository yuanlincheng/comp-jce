package com.ylc.jce;

import org.junit.Assert;
import org.junit.Test;

/**
 * author: tree
 * version: 1.0
 * since:
 * date: 2018/4/15 23:49
 * description:
 * own:
 */
public class JceFactoryTest {

    @Test
    public void testCreate() throws Exception {
        JceFactory jceFactory = new JceFactory();
        //获取BC加解密对象
        Assert.assertNotNull(JceFactory.getJceInstance(1));
        Assert.assertNotNull(JceFactory.getJceInstance(0));
    }
}