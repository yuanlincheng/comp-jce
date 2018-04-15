package com.ylc.jce;

import com.ylc.util.JceBCUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * author: tree
 * version: 1.0
 * since:
 * date: 2018/4/15 16:26
 * description: 基础加解密模块组件(工厂模式)
 * own:
 */
public class JceFactory {

    private static final Logger logger = LoggerFactory.getLogger(JceFactory.class);

    /**
     * 根据算法提供商类型提供对应的加解密对象实例
     * @param jceProType    算法提供商类型：1表示BC ，2表示其它算法提供商
     * @return JceCipherObject 加解密对象类
     */
    static JceCipherObject getJceInstance(int jceProType){
        // 此处调试输出
        logger.debug("[Start get JceCipherObject][{}][1:BC][2:OTHER]",jceProType);
        //定义加解密对象
        JceCipherObject jceCipherObject;
        //根据算法提供商类型，创建对应加解密对象
        switch (jceProType) {
            case 1: {
                //1 表示BC
                jceCipherObject = new JceBCUtil();
                break;
            }
            default:
                jceCipherObject = new JceBCUtil();
                break;
        }
        //返回加解密对象实例子类
        return jceCipherObject;
    }
}
