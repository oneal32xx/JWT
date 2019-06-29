using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JwtTest.Jwt
{
    public class JwtHelper
    {
        private static readonly JwtHelper instance = new JwtHelper();
        private string aesKey = string.Empty;
        private string aesiv = string.Empty;
        private string jwtSecret = string.Empty;
        private int expiryTime = 60 * 60;

        private JwtHelper()
        {
            string today = DateTime.Now.ToString("yyyyMMdd");
            aesKey = today + today + today + today;
            aesiv = today + today;
            jwtSecret = "jwtSecret";
        }

        public static JwtHelper GetInstance()
        {
            return instance;
        }

        public byte[] GetJwtSecret()
        {
            return System.Text.Encoding.GetEncoding("utf-8").GetBytes(jwtSecret);
        }

        public string EncryptAES(string text)
        {
            var sourceBytes = System.Text.Encoding.UTF8.GetBytes(text);
            var aes = new System.Security.Cryptography.RijndaelManaged();
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.Key = System.Text.Encoding.UTF8.GetBytes(aesKey);
            aes.IV = System.Text.Encoding.UTF8.GetBytes(aesiv);
            var transform = aes.CreateEncryptor();
            return System.Convert.ToBase64String(transform.TransformFinalBlock(sourceBytes, 0, sourceBytes.Length));
        }

        public string DecryptAES(string text)
        {
            var encryptBytes = System.Convert.FromBase64String(text);
            var aes = new System.Security.Cryptography.RijndaelManaged();
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.Key = System.Text.Encoding.UTF8.GetBytes(aesKey);
            aes.IV = System.Text.Encoding.UTF8.GetBytes(aesiv);
            var transform = aes.CreateDecryptor();
            return System.Text.Encoding.UTF8.GetString(transform.TransformFinalBlock(encryptBytes, 0, encryptBytes.Length));
        }


        public byte[] Base64UrlDecode(string arg) // This function is for decoding string to   
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding  
            s = s.Replace('_', '/'); // 63rd char of encoding  
            switch (s.Length % 4) // Pad with trailing '='s  
            {
                case 0: break; // No pad chars in this case  
                case 2: s += "=="; break; // Two pad chars  
                case 3: s += "="; break; // One pad char  
                default:
                    throw new System.Exception(
                "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder  
        }

        public bool checkExp(int reciveExp)
        {
            var time = Math.Abs(GetServerExp() - reciveExp);

            //Token 超過時間
            return (time > expiryTime) ? false : true;
        }


        public int GetServerExp()
        {
            var endDateTime = DateTime.UtcNow;
            var startDateTime = DateTime.UtcNow.Date;
            int serverExp = (int)(endDateTime.Subtract(startDateTime).TotalSeconds);
            return serverExp;
        }
    }
}