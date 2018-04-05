package com.ylc.jce;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 文件名：
 * 作者：tree
 * 时间：2017/4/21
 * 描述：
 * 版权：亚略特
 */
public class JceCipherObjectTest {

    JceCipherObject jce = null;

    @Before
    public void setUp() throws Exception {
        jce = JceFactory.getJceInstance(1);
    }

    @Test
    public void testEncrypt() throws Exception {
        String key = "SM4Key0123456789";
        String plain = "ylc";
        //测试RSA内部加密
//        assertNotNull(jce.encrypt("RSA", "RSA/ECB/PKCS1Padding", plain.getBytes("UTF-8"), 1, 1, 1024, null));
         //测试RSA外部加密
//        key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVCVlw6KG0TYXFxhuBUAeHe0hjLrmgkIGL0KllDQaQjesLnGLkDZ8yj0r7vCx2PWbA1yVcvj7kTw3cHQBll/ev3y8tbQFzYCufWGQApM6wIoF+lId87x4N1zB2QBsQ1E9ysPHgeoIRhGmPWIkGH4c41HZUsDrAaFbMGr2P//3YjQIDAQAB";
//        assertNotNull(jce.encrypt("RSA", "RSA/ECB/PKCS1Padding", plain.getBytes("UTF-8"), -2, 1, 1024, key));
        //测试AES加密
        key = Base64.getEncoder().encodeToString("Aratek123456.com".getBytes("UTF-8"));
        assertNotNull(jce.encrypt("AES", "AES/ECB/PKCS5PADDING", plain.getBytes("UTF-8"), -2, 3, -1, key));
        //测试SM4加密
//        assertNotNull(jce.encrypt("SM4", "SM4/ECB/PKCS5Padding", plain.getBytes("UTF-8"), 1, 3, -1, null));
        //测试加密机外部密钥SM2加密
//        key = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAETuSQynzV4LiOH0XClF03pzNdbzjxW/BpmW4u7yBrE2tuKcGuFfYRSioW+aiH2Qxq5Y73aT7fr9EhPIRA1yBejw==";
//        assertNotNull(jce.encrypt("SM2", "SM2", plain.getBytes("UTF-8"), -2, 1, -1,key));

    }

    @Test
    public void testDecrypt() throws Exception {
        String plain = "k7s8LDz5lva0C4vVb4+NO4wdXQ8jaKXfZNPIpbwb0XWBmV+oZC7qjOTD9+o7LnCqkdZ12O7oIVjMIAQGZS09phrDj1hK1I9AvJAaOd5Fo7xzNjvffFL11FUi+a4Nm5GDmxBicyoKTMZThleuLSzdIA==";
        String key = "SM4Key0123456789";
        //测试RSA内部解密
//        plain ="jXr8G0aHsw+UZ8h1+z/ZXnHyd2hZLO114g8jAatYOpNvRADZ8Ov083txSOOh3neF6/z33xQf00n7A/7nISojeyX4RDU2sSmxTJYaBMdYdLkoAhHEX+0z/Eg/ITcul4k3qjAuMoBwE7mnYS9D6UYJ+3lTk3sErjcjDbdzyVBZozw=";
//        assertNotNull(jce.decrypt("RSA", "RSA/ECB/PKCS1Padding", plain, 1, 2, null, 1));
        //测试AES解密
        plain = "vp5TQZgPFDmhCuT7l/VuBw==";
        assertNotNull(jce.decrypt("AES", "AES/ECB/PKCS5PADDING", plain, 1, 3,null, 1));
        //测试SM4解密
//         plain = "SQVgU8hiSzgLYWllUSmtTQ==";
//        assertNotNull(jce.decrypt("SM4", "SM4/ECB/PKCS5Padding", plain, 1, 3, null, 1));
        //测试SM2解密
//        plain = "MHkCIQDkWJu4pZhbRXycustwUQNEw51ASrG7e7e3OoP8FJN2gwIgJHkFIveRH95+DEiLOq0vi8SAAvRFU5kYkRz3GLvhQA8EIEc2mESK8UhzTMZQ3DvWDn9lGnbO4QlxqTBKYgO3fJkCBBBWAnaAP61++J/x2g7HhHTn";
//        key = "MGgCAQAwEwYHKoZIzj0CAQYIKoEcz1UBgi0ETjBMAgEBAgEBoUQDQgAEhx35njSywco0OKBaksDntNucl7EK06SDJY2Vr0Xd0XrB4TBq9/cWHedRUtii3S25rmZ26j0LWN6/WSfSHn3YNA==";
//        assertNotNull(jce.decrypt("SM2", "SM2", plain, 1, 2, null, 2));
//        plain = "MGwCIBCa82sbW+0RNHwOnHXdwk/dzmed7fn0MP5Tzn8IlRgBAiEA5V7ZlBNgGLmzqmOqy8GbJdS7WW5X7bbqouBt2o9m45sEIPRgSalKDf6STm6A/xzfuOdJPxfU/u9MP17Goe36YfiYBAOUkpg=";
//        key = "MGgCAQAwEwYHKoZIzj0CAQYIKoEcz1UBgi0ETjBMAgEBAgEBoUQDQgAEhx35njSywco0OKBaksDntNucl7EK06SDJY2Vr0Xd0XrB4TBq9/cWHedRUtii3S25rmZ26j0LWN6/WSfSHn3YNA==";
//        assertNotNull(jce.decrypt("SM2", "SM2", plain, -2, 2, key, 1));
        //测试SM4解密
//        plain = "RgW36OCnq7fbPrNxuwA8dz+YuVwrG6Rvgtwfja4AxIU=";
//        key = "4z3V+yI79OWUIrRzqX6UJA==";
//        assertNotNull(jce.decrypt("SM4", "SM4/CBC/PKCS5Padding", plain, -2, 3, key, 1));
    }

    @Test
    public void testSign() throws Exception {
        assertNotNull(jce.sign("RSA", "SHA1WithRSA", "ylc", -1, 1024, null));
    }

    @Test
    public void testVerifySign() throws Exception {
        String keyBase64Data = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDExNT0QlC5UH4hR+Ym4ONosVVCGEBurbAF7VanA6cQv4ULaElK/MJkb6eViWAEEIULLPh6axX2aXUKIXSnnZ9fKaJsVF1WX3CfUqES+yeSex3OrU+MEgph7LQ0TzWp1wOa4gVqVfvo7cNkr43nk93w4GEtd99vPx4XpvNCotnnawIDAQAB";
        String signData = "mtM6gAo2XbdRumijlVJt8kgu+WHd/iDEZtGCdxacEKBchlK6Ebo3afCdZL6LRBhqaPWNnAw1qCdzkSCR0fr54uHWva1EHeqC/K5hFcuEcsY6TaQJrg1NU4gUKaVQ1IlKKJs1aUob5QGJK1Qm6pEUr0XVqVlrhXY5jqeZxF+xLwQ=";
        String plainData = "FingerXmlData";
        assertTrue(jce.verifySign("RSA","SHA1WithRSA",plainData,signData,-2,keyBase64Data));
    }

    @Test
    public void testVerifyCert() throws Exception {
        String certData = "MIIE9TCCA92gAwIBAgIMSH26QQMlSyGz/B4SMA0GCSqGSIb3DQEBBQUAMCsxCzAJBgNVBAYTAkNOMQwwCgYDVQQKDANNRkExDjAMBgNVBAMMBU1GQUNBMB4XDTE3MDMxNTA4MjQ1OVoXDTIwMDMxNDA4MjQ1OVowfDELMAkGA1UEBgwCQ04xDDAKBgNVBAoMA01GQTEYMBYGA1UECwwP6am75aSW5L2/6aKG6aaGMRYwFAYDVQQqDA3oiKrkv6HmtYvor5UyMS0wKwYDVQQDDCRaRFNDQzc3MzlENjA4MDkwMDAwMTFGQUIxMjM3NEZGOTE2NDAwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM1y+G6Ri2gSYYGBxfhnFyIj8llrOcIv5LfmHzB79ZQC+F66wCaglOqQ2oSX7LMX0M5rKjMGtd6c1hvEwiWE1EPEoHxEIcvk4o6JW1374k8d1krKNgX79mh9yx6zNBdhQX7S2unDyjXz3J/wyoIAfh6q7aJ4tWzWQtnET+AED0R/AgMBAAGjggJKMIICRjAPBgNVHRMBAQAEBTADAQEAMCAGA1UdJQEBAAQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAOBgNVHQ8BAQAEBAMCAMAwFAYJYIZIAYb4QgEBAQEABAQDAgCAMCIGA1UdIwEBAAQYMBaAFBjBe+dfSeXInjF+kx8luMs/yGiOMIHTBggrBgEFBQcBAQEBAASBwzCBwDCBhgYIKwYBBQUHMAKGemxkYXA6Ly8xNzIuMTYuOS4xODozODkvQ049TUZBQ0EsQ049TUZBQ0EsT1U9Y0FDZXJ0aWZpY2F0ZXMsbz1tZmEuY29tP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MDUGCCsGAQUFBzAChilodHRwOi8vMTcyLjE2LjguMjo4ODgwL2Rvd25sb2FkL01GQUNBLmNlcjCBzgYDVR0fAQEABIHDMIHAMIG9oIG6oIG3hoGJbGRhcDovLzE3Mi4xNi45LjE4OjM4OS9DTj1NRkFDQSxDTj1NRkFDQSxvdT1DUkxEaXN0cmlidXRlUG9pbnRzLG89bWZhLmNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Y2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGKWh0dHA6Ly8xNzIuMTYuOC4yOjg4ODAvZG93bmxvYWQvTUZBQ0EuY3JsMCAGA1UdDgEBAAQWBBRCw7SOxHY4SjQbpaSuge2wwDO1FzANBgkqhkiG9w0BAQUFAAOCAQEABYywajg8AHch4SZ1zrYB3Gb2gNvV2eV0S20A1kJv/rhqll1o74Fb+tia1ldp96RBhp7mDWUUNVD0eS7i1okg2Em84oCokssGkLwSGo18R40blEpgRVgf1zIYJj7nZnzXPIqUZadeDD44WA33wOfHGGgBRBy/XNFIgzrpEjY5Tz/DwG6BvaWjBIquEp8PSRumAV4hRPUl2HlPAOP7v9baZ+qY5Z6gsVtZYhgbvq0p7idfA3qEJx2WB2LiJtYRyfMVM1bjVxRLLzZL8g5YAxG+hOTIlpznBxTvY97xvaG3MbVxoqVQ2/w2GY8Le2SuHQZ9XqOIQprPyKoKWOmCo3qrDQ==";
        String rootFilePath = "D:/MFACA.cer";
        assertTrue(jce.verifyCert(certData,rootFilePath));
    }

    @Test
    public void testChangeByteToKey() throws Exception {
        String key = "";
        //测试转换AES密钥
        key = "TVXnwzWem3ULpTb9d9veIUTQ0xRs+r3UfnWozmyZyWw=";
        assertNotNull(jce.changeByteToKey("AES",key,3));
        //测试转换SM2公钥
        key = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAETuSQynzV4LiOH0XClF03pzNdbzjxW/BpmW4u7yBrE2tuKcGuFfYRSioW+aiH2Qxq5Y73aT7fr9EhPIRA1yBejw==";
        assertNotNull(jce.changeByteToKey("SM2",key,1));
    }

    @Test
    public void testBatchSm2Dec() throws Exception{
        boolean flag = true;
        StringBuffer sb = new StringBuffer();
        Files.readAllLines(Paths.get("F:\\enc.txt"), StandardCharsets.UTF_8).forEach(x -> sb.append(x));
        String[] str = sb.toString().split(";");
        String key = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQIgFUpdUcvdCLa7/1Kuf47OUWC/XDRCMTKbHuxdnlkgUMihRANCAARO5JDKfNXguI4fRcKUXTenM11vOPFb8GmZbi7vIGsTa24pwa4V9hFKKhb5qIfZDGrljvdpPt+v0SE8hEDXIF6P";
        for(String plain:str){
            String[] str1 =plain.split(",");
            if (!(str1[0].equals(jce.decrypt("SM2", "SM2", str1[1], -2, 2, key, 1)))) {
                flag = false;
            }
        }
        assertTrue(flag);
    }

}