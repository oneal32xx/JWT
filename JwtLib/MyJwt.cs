using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.Caching;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtLib
{
    public sealed class MyJwt
    {
        private static readonly MyJwt instance = new MyJwt();
        private static MemoryCache _cache = MemoryCache.Default;
        private static JwtOptions _jwtOption = new JwtOptions();

        private MyJwt()
        {

        }

        public static MyJwt Instance
        {
            get
            {
                return instance;
            }
        }

        public void initOption(JwtOptions jwtOption)
        {
            _jwtOption = jwtOption;
            if (jwtOption.SecurityMode == SecurityMode.Default)
            {
                var policy = new CacheItemPolicy();
                policy.AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(jwtOption.TokenExpire);
                var Rkey = Guid.NewGuid().ToString();
                _cache.Set(jwtOption.UserName, Rkey, policy);
            }
        }

        public string CreateToken()
        {
            DateTime issuedAt = DateTime.UtcNow;
            DateTime expires = DateTime.UtcNow.AddMinutes(_jwtOption.TokenExpire);

            //http://stackoverflow.com/questions/18223868/how-to-encrypt-jwt-security-token
            var tokenHandler = new JwtSecurityTokenHandler();
            //create the jwt
            var token =
                (JwtSecurityToken)tokenHandler.CreateJwtSecurityToken(issuer: _jwtOption.Issuer,
                                                                      audience: _jwtOption.Audience,
                                                                      subject: getClaimsIdentity(),
                                                                      notBefore: issuedAt,
                                                                      expires: expires,
                                                                      signingCredentials: getSigningCredentials());
            var tokenString = tokenHandler.WriteToken(token);
            return tokenString;
        }


        public bool ValidateToken(string token, out ClaimsPrincipal claims)
        {
            bool result = false;
            claims = null;
            try
            {
                SecurityToken securityToken;
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                TokenValidationParameters validationParameters = new TokenValidationParameters()
                {
                    ValidAudience = _jwtOption.Audience,
                    ValidIssuer = _jwtOption.Issuer,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    LifetimeValidator = this.LifetimeValidator,
                    IssuerSigningKey = getSymmetricSecurityKey()
                };
                claims = handler.ValidateToken(token, validationParameters, out securityToken);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
        /// Valid token expire
        /// </summary>
        /// <param name="notBefore"></param>
        /// <param name="expires"></param>
        /// <param name="securityToken"></param>
        /// <param name="validationParameters"></param>
        /// <returns></returns>
        private bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (expires != null)
            {
                if (DateTime.UtcNow < expires) return true;
            }
            return false;
        }

        private SymmetricSecurityKey getSymmetricSecurityKey()
        {
            var security = string.Empty;
            if (_jwtOption.SecurityMode == SecurityMode.Default)
            {
                if (!_cache.Contains(_jwtOption.UserName))
                    throw new Exception("Default Mode Error: guid values not found");

                security = _cache.Get(_jwtOption.UserName).ToString();
            }
            else if (_jwtOption.SecurityMode == SecurityMode.Custom)
            {
                security = _jwtOption.SecurityKey;
            }

            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(security));
            return securityKey;
        }

        private SigningCredentials getSigningCredentials()
        {
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(getSymmetricSecurityKey(), Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);
            return signingCredentials;
        }

        /// <summary>
        /// create a identity and add claims to the user which we want to log in
        /// </summary>
        /// <returns></returns>
        private ClaimsIdentity getClaimsIdentity()
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, _jwtOption.UserName)
            });
            return claimsIdentity;
        }
    }

    public class JwtOptions
    {
        public SecurityMode SecurityMode { get; set; } = SecurityMode.Custom;
        public int TokenExpire { get; set; } = 5;
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string SecurityKey { get; set; } = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";
        public string UserName { get; set; }

        public bool checkDataEmpty()
        {
            if (SecurityMode == SecurityMode.Custom)
            {
                if (string.IsNullOrEmpty(Audience) || string.IsNullOrEmpty(Issuer) || string.IsNullOrEmpty(UserName) || string.IsNullOrEmpty(SecurityKey))
                {
                    return false;
                }
            }
            else if (SecurityMode == SecurityMode.Default)
            {
                if (string.IsNullOrEmpty(Audience) || string.IsNullOrEmpty(Issuer) || string.IsNullOrEmpty(UserName))
                {
                    return false;
                }
            }
            return true;
        }
    }

    public enum SecurityMode
    {
        Custom,
        Default,
    }
}
