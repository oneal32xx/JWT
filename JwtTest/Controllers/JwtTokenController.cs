using Jose;
using JwtTest.Jwt;
using JwtTest.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;

namespace JwtTest.Controllers
{


    public class JwtTokenController : ApiController
    {

        /// <summary>
        /// 使用者登入後回傳 Token
        /// </summary>
        /// <param name="loginData"></param>
        /// <returns></returns>
        // api/JwtToken
        public object Post(LoginData loginData)
        {
            var jwt = JwtHelper.GetInstance();

            // TODO: 模擬登入檢查帳號密碼
            if (loginData.Username == "user" && loginData.Password == "123456")
            {

                //組payLoad
                var payload = new JwtAuth()
                {
                    name = loginData.Username,
                    exp = jwt.GetServerExp()
                };

                //gen Token
                var jwtToken = Jose.JWT.Encode(payload, jwt.GetJwtSecret(), JwsAlgorithm.HS256);

                //Encrypt Token
                var returnToken = jwt.EncryptAES(jwtToken);

                return new
                {
                    Result = true,
                    token = returnToken
                };
            }
            else
            {
                throw new UnauthorizedAccessException("帳號密碼錯誤");
            }
        }
    }
}
