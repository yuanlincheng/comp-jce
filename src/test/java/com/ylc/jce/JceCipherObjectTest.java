package com.ylc.jce;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * author: tree
 * version: 1.0
 * since:
 * date: 2018/4/16 1:04
 * description:
 * own:
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
        key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwIJ2Sk4uS6uA2X8Q/A0etdIvpF8q3Xf+yqSDvfq17ZlSxhNitXlCEGOqAUbnTpn0mBHF7jAZKfQQd+BdSjhKPzqBoIFNXqzyhQ+K6mOrUUl4YpyNdKxvSJnvK0jOX9reoRxiMLCjfxwv+viOvF35Ohm7M1lt+Rk3cACLXwSwfzwIDAQAB";
        assertNotNull(jce.encrypt("RSA", "RSA/ECB/PKCS1Padding", plain.getBytes("UTF-8"), -2, 1, 1024, key));
        //测试AES加密
//        key = Base64.getEncoder().encodeToString("Aratek123456.com".getBytes("UTF-8"));
//        assertNotNull(jce.encrypt("AES", "AES/ECB/PKCS5Padding", plain.getBytes("UTF-8"), -2, 3, -1, key));
        //测试AES加密，1号索引位
//        assertNotNull(jce.encrypt("AES", "AES/ECB/PKCS5Padding", plain.getBytes("UTF-8"), 1, 3, -1, null));
        //测试SM4加密
//        assertNotNull(jce.encrypt("SM4", "SM4/ECB/PKCS5Padding", plain.getBytes("UTF-8"), 1, 3, -1, null));
    }

    @Test
    public void testDecrypt() throws Exception {
        String plain = "k7s8LDz5lva0C4vVb4+NO4wdXQ8jaKXfZNPIpbwb0XWBmV+oZC7qjOTD9+o7LnCqkdZ12O7oIVjMIAQGZS09phrDj1hK1I9AvJAaOd5Fo7xzNjvffFL11FUi+a4Nm5GDmxBicyoKTMZThleuLSzdIA==";
        String key = "SM4Key0123456789";
        //测试RSA内部解密
//        plain ="Ed5+yvBBWh8bV8wV5FD8C4s6i+55NVueG49qFhtkRwTvMY2MvJK7V4cg3v29ZrE62g8bYA/qECK8uEKJCBwE0lFBO2CVvLRyMofrPcLOc9PQVtUUK0kkKm3wJlKggwX9iL5O2DMNc6VzeNLWmFpC719kglRMY3nk4jnfD+eph3k=";
//        assertNotNull(jce.decrypt("RSA", "RSA/ECB/PKCS1Padding", plain, 1, 2, null, 1));
        //测试RSA外部解密
        plain ="Ed5+yvBBWh8bV8wV5FD8C4s6i+55NVueG49qFhtkRwTvMY2MvJK7V4cg3v29ZrE62g8bYA/qECK8uEKJCBwE0lFBO2CVvLRyMofrPcLOc9PQVtUUK0kkKm3wJlKggwX9iL5O2DMNc6VzeNLWmFpC719kglRMY3nk4jnfD+eph3k=";
        key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALAgnZKTi5Lq4DZfxD8DR610i+kXyrdd/7KpIO9+rXtmVLGE2K1eUIQY6oBRudOmfSYEcXuMBkp9BB34F1KOEo/OoGggU1erPKFD4rqY6tRSXhinI10rG9Ime8rSM5f2t6hHGIwsKN/HC/6+I68Xfk6GbszWW35GTdwAItfBLB/PAgMBAAECgYARnGFFG720Bgo/RZog1toe7O1kdD2P0jVUDvc9G0SLdzL2wRrNUwXn/3nLNODI2fffikgym1CxuAhmWr0yQwR18/sMiKydINir0XQgO3YQbP3OBxipfAmoTUbA2qIyN8VN2PS8bznYlW8CtTV/KB1sM4Sb8x5tgtdMiRDGnJFQsQJBAOsUVZT5sdquoto8xmZZtW5LB4BEiH12TEiWevcWM6cc5DukJO7Zp3Ohojg9dWUmyEIb0bhj+ISwfrchmqvkBVcCQQC/zTbs+HWC0i1dgDp0V7Ks+3hoR3dSdfdbN7J7jqZzfGMmlTQafZlQ5Fv3sNjJ9EjHefNagSquytKWG+7wA/ZJAkAPqhA12BmY19A0OJ6DzXCAg/FhA7AQpCRbJePVuR4CAbPXoY1weQJmexvDIZ1D+zyW4yGrZsX1mYkoDM4wrAYLAkA+7xcWqm/kfRJlm62SfzQhjmHz1X9Rj2OaiqwF3si/HBFsl4iBKLUl1chXfa+klINM8Lbo+3kF4Yc3ufKszqABAkEAmyhXBk1yFN4uGuPipKL7mCZz4+s/hwPUa2eaxncEnt1Sh+HSNoKbHslii/36D3QTO2K/zeCNdBIVTffoHi+n6g==";
        assertNotNull(jce.decrypt("RSA", "RSA/ECB/PKCS1Padding", plain, -2, 2, key, 1));
        //测试AES解密
//        plain = "ttyyMop3WTDLVEwFiXynIQ==";
//        assertNotNull(jce.decrypt("AES", "AES/ECB/PKCS5Padding", plain, 1, 3,null, 1));
        //测试AES解密
//        plain = "TwUWLP6uH4u540KfQNQqCQ==";
//        key = Base64.getEncoder().encodeToString("Aratek123456.com".getBytes("UTF-8"));;
//        assertNotNull(jce.decrypt("AES", "AES/ECB/PKCS5Padding", plain, -2, 3,key, 1));
        //测试SM4解密
//         plain = "TjOvTCCXiTPcNfERGa7ang==";
//        assertNotNull(jce.decrypt("SM4", "SM4/ECB/PKCS5Padding", plain, 1, 3, null, 1));
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
        //测试转换AES密钥
        String key = "TVXnwzWem3ULpTb9d9veIUTQ0xRs+r3UfnWozmyZyWw=";
        assertNotNull(jce.changeByteToKey("AES",key,3));
    }

    @Test
    public void testBatchSm2Dec() throws Exception{
//        boolean flag = true;
//        StringBuffer sb = new StringBuffer();
//        Files.readAllLines(Paths.get("F:\\enc.txt"), StandardCharsets.UTF_8).forEach(x -> sb.append(x));
//        String[] str = sb.toString().split(";");
//        String key = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQIgFUpdUcvdCLa7/1Kuf47OUWC/XDRCMTKbHuxdnlkgUMihRANCAARO5JDKfNXguI4fRcKUXTenM11vOPFb8GmZbi7vIGsTa24pwa4V9hFKKhb5qIfZDGrljvdpPt+v0SE8hEDXIF6P";
//        for(String plain:str){
//            String[] str1 =plain.split(",");
//            if (!(str1[0].equals(jce.decrypt("SM2", "SM2", str1[1], -2, 2, key, 1)))) {
//                flag = false;
//            }
//        }
//        assertTrue(flag);
    }

}