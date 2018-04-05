package com.ylc.jce;

import org.junit.Assert;
import org.junit.Test;

/**
 * 文件名：
 * 作者：tree
 * 时间：2017/4/21
 * 描述：
 * 版权：亚略特
 */
public class JceFactoryTest {

    @Test
    public void testCreate() throws Exception {
        //获取非加密机加解密对象
        Assert.assertNotNull(JceFactory.getJceInstance(1));
    }
}