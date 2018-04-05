package com.ylc.jce;

import com.ylc.util.JceBCUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author: tree
 * @version: 1.0
 * date: 2017/4/21
 * @description: 用于系统的加解密模块，工厂模式
 * own: Aratek
 */
public class JceFactory {

    private static final Logger logger = LoggerFactory.getLogger(JceFactory.class);

    /**
     * 根据算法提供商类型提供对应的加解密对象实例
     * @param jceProType    算法提供商类型：1表示BC 对应非加密机版本 ，2表示对应加密机版本
     * @return JceCipherObject 加解密对象类
     */
    public static JceCipherObject getJceInstance(int jceProType){
        // 此处调试输出
        logger.debug("[Start get JceCipherObject][{}][1:BC][2:SWXA]",jceProType);
        //定义加解密对象
        JceCipherObject jceCipherObject = null;
        //根据算法提供商类型，创建对应加解密对象
        switch (jceProType) {
            case 1: {
                //1 表示BC 对应非加密机版本
                jceCipherObject = new JceBCUtil();
                break;
            }
            default:
                break;
        }
        //返回加解密对象实例子类
        return jceCipherObject;
    }

    /**
     * 根据算法提供商类型和配置文件路径提供对应的加解密对象实例
     * @param jceProType    算法提供商类型：1表示BC 对应非加密机版本 ，2表示对应加密机版本
     * @param url   加密机配置文件绝对路径，主要用于指定加密机IP
     * @return JceCipherObject 加解密对象类
     */
    public static JceCipherObject getJceInstance(int jceProType,String url){
        // 此处调试输出
        logger.info("[Start get JceCipherObject][{}][1:BC][2:SWXA][{}]",jceProType,url);
        //定义加解密对象
        JceCipherObject jceCipherObject = null;
        //根据算法提供商类型，创建对应加解密对象
        switch (jceProType) {
            case 1: {
                //1 表示BC 对应非加密机版本
                jceCipherObject = new JceBCUtil();
                break;
            }
            default:
                break;
        }
        //返回加解密对象实例子类
        return jceCipherObject;
    }
}
