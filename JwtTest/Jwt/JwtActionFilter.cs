using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Jose;

namespace JwtTest.Jwt
{
    public class JwtActionFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            var jwt = JwtHelper.GetInstance();

            if (actionContext.Request.Headers.Authorization == null || actionContext.Request.Headers.Authorization.Scheme != "Bearer")
            {
                setErrorResponse(actionContext, "驗證錯誤");
            }
            else
            {
                try
                {
                    //Decrypt HttpHeader
                    var reciveJwt = jwt.DecryptAES(actionContext.Request.Headers.Authorization.Parameter);

                    //Decode JWT Token
                    var jwtObject = Jose.JWT.Decode<JwtAuth>(reciveJwt, jwt.GetJwtSecret(), JwsAlgorithm.HS256);

                    //check EXP time
                    if (!jwt.checkExp(jwtObject.exp)){
                        setErrorResponse(actionContext, "驗證已超時!");
                    }

                }
                catch (Exception ex)
                {
                    setErrorResponse(actionContext, ex.Message);
                }
            }

            base.OnActionExecuting(actionContext);
        }

        private static void setErrorResponse(HttpActionContext actionContext, string message)
        {
            var response = actionContext.Request.CreateErrorResponse(HttpStatusCode.Unauthorized, message);
            actionContext.Response = response;
        }
    }
}