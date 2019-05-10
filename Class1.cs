using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace WinFrmTest
{
    class Class1
    {
        /// <summary>  
        /// MD5加密。  
        /// </summary>  
        public static string MD5Encrypt(string originalString)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] palindata = Encoding.Default.GetBytes(originalString);
            byte[] encryptdata = md5.ComputeHash(palindata);

            return Convert.ToBase64String(encryptdata);
        }

        /// <summary>  
        /// RAS加密。  
        /// </summary>  
        public static string RSAEncrypt(string originalString)
        {
            CspParameters param = new CspParameters();
            param.KeyContainerName = "DVIEW";

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(param))
            {
                byte[] plaindata = Encoding.Default.GetBytes(originalString);
                byte[] encryptdata = rsa.Encrypt(plaindata, false);

                return Convert.ToBase64String(encryptdata);
            }
        }

        /// <summary>  
        /// RAS解密。  
        /// </summary>  
        public static string RSADecrypt(string securitylString)
        {
            CspParameters param = new CspParameters();
            param.KeyContainerName = "DVIEW";
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(param))
            {
                byte[] encryptdata = Convert.FromBase64String(securitylString);
                byte[] decryptdata = rsa.Decrypt(encryptdata, false);
                return Encoding.Default.GetString(decryptdata);
            }
        }

        /// <summary>  
        /// DES加密。  
        /// </summary>  
        public static string DESEncrypt(string originalString)
        {
            string securtyString = null;
            string key = "12345678";
            string iv = "87654321";
            byte[] btKey = Encoding.UTF8.GetBytes(key);
            byte[] btIV = Encoding.UTF8.GetBytes(iv);
            byte[] inData = Encoding.UTF8.GetBytes(originalString);

            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(btKey, btIV), CryptoStreamMode.Write);

            cs.Write(inData, 0, inData.Length);
            cs.FlushFinalBlock();

            securtyString = Convert.ToBase64String(ms.ToArray());
            cs.Close();
            ms.Close();

            return securtyString;
        }

        /// <summary>  
        /// DES解密。  
        /// </summary>  
        public static string DESDecrypt(string securityString)
        {
            byte[] inData = null;
            try
            {
                inData = Convert.FromBase64String(securityString);
            }
            catch (Exception)
            {
                return null;
            }

            string originalString = null;
            string key = "12345678";
            string iv = "87654321";
            byte[] btKey = Encoding.UTF8.GetBytes(key);
            byte[] btIV = Encoding.UTF8.GetBytes(iv);

            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(btKey, btIV), CryptoStreamMode.Write);

            cs.Write(inData, 0, inData.Length);
            try
            {
                cs.FlushFinalBlock();
            }
            catch (Exception)
            {
                ms.Close();
                return null;
            }


            originalString = Encoding.UTF8.GetString(ms.ToArray());
            cs.Close();
            ms.Close();

            return originalString;
        }

        private static string publicKey = "<RSAKeyValue><Modulus>nZadHWtoT0ydValZ8TSKqkEK8c5A281aA61LHXjnUrOSJS3iWLUGjMzww8nMgj1jnVofSD0annSNdm9f/nqHXeOKxmIEw54Qb1g4iwaNrzi73j6X/8DgM0EdinKDYDYV5O1HfWv8NOtSatOn6++9ne++kxgGMzXzlapLmA8FZL4bxU3TuvyoccN4qHAFKijjxgGmvY2fox1a4gShmtatkWW6a7M/fP592EfWI01h9IBnwNQOcRPOuWf/6N8BxySb4vUaEjm8EtDoX/ysIAO4Jmozz6mvYnNegILYGnnzZxON2vfUDK1WoPADLx7pwGSrB7Rcwu2mBQfm03kTTGVsdQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        private static string privateKey = "<RSAKeyValue><Modulus>nZadHWtoT0ydValZ8TSKqkEK8c5A281aA61LHXjnUrOSJS3iWLUGjMzww8nMgj1jnVofSD0annSNdm9f/nqHXeOKxmIEw54Qb1g4iwaNrzi73j6X/8DgM0EdinKDYDYV5O1HfWv8NOtSatOn6++9ne++kxgGMzXzlapLmA8FZL4bxU3TuvyoccN4qHAFKijjxgGmvY2fox1a4gShmtatkWW6a7M/fP592EfWI01h9IBnwNQOcRPOuWf/6N8BxySb4vUaEjm8EtDoX/ysIAO4Jmozz6mvYnNegILYGnnzZxON2vfUDK1WoPADLx7pwGSrB7Rcwu2mBQfm03kTTGVsdQ==</Modulus><Exponent>AQAB</Exponent><P>0nt2h1Dk8qR9qAukRtM2HZn6aTaURnpPm3K1NFCjRykXtcUFEn+d6rUcpW2EF1oSNd/S5o9Mvcs6KUGhG2cHdlHlMt+cOYzZuPb5esLfa7z6TZ8NOcL/yOKZ3FU+rl2x2Gx6GmECpWmJbGh3xJkZtwIxuesHs4zMki4Vo4V1CM8=</P><Q>v6rh2f/bZxJfQCVh7qppXY/JS3QAdBZIU5V+N73zDEe6lw5C7UOQDCSB+bys8zi24Bf8TSfSy1lBN6p8W2YEAPrNFB3tHPe4erHYw1RxWixIHaOle4bjBiJoogGAKPAXRDkxB9xh+n67d/E8/+OMeLEBh8mTzRGKQKdbQ2Fc/3s=</Q><DP>Y0JqASI69dpwj6D91ZChQpBssNVWU242wH31yjgE5/gPAF9rJvAbzqWeXr0ov8JwOAvXb3dAn3iJcw9KJJwPvtKcHcOp7tHnkvyVZjkkF7DE8XoCSK0W5utF18wzhRMWXZO6eVoqX0tHzWHuqT3yDIXyYVTfCuNpTb6B4d179a0=</DP><DQ>l1lx5Po0H40TaAzc62DnuPj8xDdC0Gh0DoSi2ZOGJDFT90pMsRzD18LQXAuQKrOjPQvTsH186BR/+lwGvQmuqbNiU7tZ7KD0rPZZK803gTQscjMyTnvyM3riUuOKd0k3pijfPczaFbsTgCAfwhTGbNuhUL9tleZ+3JUK7QcqL5c=</DQ><InverseQ>z4Ue58M3+coRO4w7tBbiz3ljYSlL8X/t3IAuiIW5KG2KhPbvtsvocHcdy5x609IBmUI1gEGnuq1SDt5w9Q8Wl3Z4oPNAAEsRJ/JkQDW/Q3A+SUKUXug+QV3OVPHP6/OMd9/wt0LiHwJOPBPCjvDwEwJrCIzgav5CLW+0+cUTLkg=</InverseQ><D>IdqcUBil5PtBhYiHIPE3pNGqRz4W4uFfqBCPZXp2v2aCS+hqisIA8TiJtJXikEwd3UziEYPG9yl0xm+wwJuT/xCF3I5sFZYcU78xDnTO9UiL23e48aF+yKQBc5+cJ4wW8gIjbIdJPBkdsINdvKrZIlfBqhnsIw5BEPLvoHABqZ1zNynldXsVMsObX3vkuF0gkwgfvAGqPGtbOwTdqw6cDgl97tODciihB45Ul/mFsCFQuY2Ia5BVbmPS19vAPnAuUvVyISyv9Hn2Gq9LyiSfM5IbXGUmXyaXHGH7ZrgIlkpOvbOHM0+cqVlhm1ldPgtqtUGzDUWKcWAzOkyJNR0P1Q==</D></RSAKeyValue>";

        public static string Decrypt(string base64code)
        {
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(privateKey);
                byte[] encryptedData = Convert.FromBase64String(base64code);
                byte[] decryptedData = RSA.Decrypt(encryptedData, false);
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                return ByteConverter.GetString(decryptedData);
            }
        }

        public static string Encrypt(string toEncryptString)
        {
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(privateKey);
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                byte[] dataToEncrypt = ByteConverter.GetBytes(toEncryptString);
                byte[] encryptedData = RSA.Encrypt(dataToEncrypt, false);
                return Convert.ToBase64String(encryptedData);
            }
        }

        /// <summary>
        /// 加密(无视长度)
        /// </summary>
        /// <param name="toEncryptString">加密明文</param>
        /// <returns></returns>
        public static string EncryptNew(string toEncryptString)
        {
            /* RSA是常用的非对称加密算法。近来有学生在项目中使用System.Security类库中的RSA加密算法时，出现了“不正确的长度”，
             * 这实际上是因为待加密的数据超长所致。.net Framework中提供的RSA算法规定，每次加密的字节数，
             * 不能超过密钥的长度值减去11,而每次加密得到的密文长度，却恰恰是密钥的长度。所以，如果要加密较长的数据，可以采用数据截取的方法
             */

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //分段加密
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                byte[] dataToEncrypt = ByteConverter.GetBytes(toEncryptString);
                RSA.FromXmlString(publicKey);
                int keySize = RSA.KeySize / 8;
                int bufferSize = keySize - 11;
                byte[] buffer = new byte[bufferSize];
                MemoryStream msInput = new MemoryStream(dataToEncrypt);
                MemoryStream msOutput = new MemoryStream();
                int readLen = msInput.Read(buffer, 0, bufferSize);
                while (readLen > 0)
                {
                    byte[] dataToEnc = new byte[readLen];
                    Array.Copy(buffer, 0, dataToEnc, 0, readLen);
                    byte[] encData = RSA.Encrypt(dataToEnc, false);
                    msOutput.Write(encData, 0, encData.Length);
                    readLen = msInput.Read(buffer, 0, bufferSize);
                }

                msInput.Close();
                byte[] result = msOutput.ToArray();    //得到加密结果
                msOutput.Close();
                return Convert.ToBase64String(result);
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="base64code">加密密文</param>
        /// <returns></returns>
        public static string DecryptNew(string base64code)
        {
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                byte[] dataEnc = Convert.FromBase64String(base64code);   //加载密文
                RSA.FromXmlString(privateKey);
                int keySize = RSA.KeySize / 8;
                byte[] buffer = new byte[keySize];
                MemoryStream msInput = new MemoryStream(dataEnc);
                MemoryStream msOutput = new MemoryStream();
                int readLen = msInput.Read(buffer, 0, keySize);
                while (readLen > 0)
                {
                    byte[] dataToDec = new byte[readLen];
                    Array.Copy(buffer, 0, dataToDec, 0, readLen);
                    byte[] decData = RSA.Decrypt(dataToDec, false);
                    msOutput.Write(decData, 0, decData.Length);
                    readLen = msInput.Read(buffer, 0, keySize);
                }

                msInput.Close();
                byte[] result = msOutput.ToArray();    //得到解密结果
                msOutput.Close();
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                return ByteConverter.GetString(result);
            }
        }
    }
}
