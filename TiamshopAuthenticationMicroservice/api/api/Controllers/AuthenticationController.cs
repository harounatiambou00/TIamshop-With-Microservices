using api.Services.JwtService;
using Microsoft.AspNetCore.Mvc;
using RestSharp;
using RestSharp.Authenticators;

namespace api.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly IJwtService _jwtService;

            public AuthenticationController(IAuthenticationService authenticationService, IJwtService jwtService)
            {
                _authenticationService = authenticationService;
                _jwtService = jwtService;
            }
            //Clients
            [HttpPost("sign-up")]
            public async Task<ActionResult<ServiceResponse<string?>>> SignUpClient(SignUpClientDTO request)
            {
                var registrationResponse = await _authenticationService.SignUpClient(request);
                if (registrationResponse.Success)
                {
                    var emailVerificationUrl = "http://localhost:3000/verify-email/" + registrationResponse.Data;
                    var emailBody = "Votre compte a été crée avec succès, vous devez maintenant confirmé votre email pour pouvoir y accéder.<br /> Pour ce faire <br /><br /> <a href=\"#URL#\"> Cliquer ici</a>";
                    emailBody = emailBody.Replace("#URL#", System.Text.Encodings.Web.HtmlEncoder.Default.Encode(emailVerificationUrl));
                    /* Ancienne version Tiamshop 1.0 :
                    var emailResponse = await _emailService.SendEmail(request.Email,  "Tiamshop, confirmation de la création de compte", emailBody);
                    return emailResponse;*/

                    //Nouvelle Version Tiamshop 2.0 : (On utilise RestSharp pour faire appel a l'api du microservice qui s'occupe des notifications mail, sms ...)
                    RestClient client = new RestClient("https:/tiamshop.azurewebsites.net/api/notifications/send-email");
                    
                    var sendEmailRequest = new RestRequest();
                    sendEmailRequest.AddParameter("from", "Tiamshop");
                    sendEmailRequest.AddParameter("to", request.Email);
                    sendEmailRequest.AddParameter("subject", "Tiamshop, confirmation de la création de compte");
                    sendEmailRequest.AddParameter("html", "<html>" + emailBody + "</html>");
                    sendEmailRequest.Method = Method.Post;

                    var response = client.Execute(sendEmailRequest);

                    if (response.IsSuccessful)
                    {
                        return new ServiceResponse<string?>
                        {
                            Data = null,
                            Success = true,
                            Message = "EMAIL_SENT_SUCCESSFULLY"
                        };
                    }
                    else
                    {
                        return new ServiceResponse<string?>
                        {
                            Data = null,
                            Success = false,
                            Message = response.Content
                        };
                    }
                }
                else
                {
                    return registrationResponse;
                }
            }
    
            [HttpPost("sign-in-with-email")]
            public async Task<ActionResult<ServiceResponse<string?>>> LoginClientWithEmail(LoginClientWithEmailDTO request)
            {
                //We will try to log the user
                var login = await _authenticationService.LoginClientWithEmail(request);
    
                //if the user is logged succesfully, we create a cookie that contains the token of the login
                if (login.Success && login.Data != null)
                {
                    Response.Cookies.Append("clientLoginJwt", login.Data, new CookieOptions
                    {
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        HttpOnly = true, //This means that the frontend can only get it but cannot access/modify it. 
                        Expires = request.RemenberMe ? DateTimeOffset.Now.AddYears(1) : DateTimeOffset.Now.AddMinutes(30)
                    });
                }
    
                /*
                 * Finally we will return a service response to inform if the login was successful or not(if not why)
                 * We return a Service Response with a null data because we don't want the frontend to access the token.
                */
                return new ServiceResponse<string?>
                {
                    Data = null,
                    Success = login.Success,
                    Message = login.Message,
                };
            }
    
            [HttpPost("sign-in-with-phone-number")]
            public async Task<ActionResult<ServiceResponse<string?>>> LoginClientWithPhoneNumber(LoginClientWithPhoneNumberDTO request)
            {
                // We will try to log the user
                var login = await _authenticationService.LoginClientWithPhoneNumber(request);
    
                //if the user is logged succesfully, we create a cookie that contains the token of the login
                if (login.Success && login.Data != null)
                {
                    Response.Cookies.Append("clientLoginJwt", login.Data, new CookieOptions
                    {
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        HttpOnly = true, //This means that the frontend can only get it but cannot access/modify it. 
                        Expires = request.RemenberMe ? DateTimeOffset.Now.AddYears(1) : DateTimeOffset.Now.AddMinutes(30)
                    });
                }
    
                /*
                 * Finally we will return a service response to inform if the login was successful or not(if not why)
                 * We return a Service Response with a null data because we don't want the frontend to access the token.
                */
                return new ServiceResponse<string?>
                {
                    Data = null,
                    Success = login.Success,
                    Message = login.Message,
                };
            }
    
            [HttpPost("sign-in-deliverer-with-email")]
            public async Task<ActionResult<ServiceResponse<string?>>> LoginDeliverertWithEmail(LoginDelivererWithEmail request)
            {
                //We will try to log the deliverer
                var login = await _authenticationService.LoginDelivererWithEmail(request);
    
                //if the deliverer is logged succesfully, we create a cookie that contains the token of the login
                if (login.Success && login.Data != null)
                {
                    Response.Cookies.Append("delivererLoginJwt", login.Data, new CookieOptions
                    {
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        HttpOnly = true, //This means that the frontend can only get it but cannot access/modify it. 
                        Expires = request.RemenberMe ? DateTimeOffset.Now.AddYears(1) : DateTimeOffset.Now.AddMinutes(30)
                    });
                }
    
                /*
                 * Finally we will return a service response to inform if the login was successful or not(if not why)
                 * We return a Service Response with a null data because we don't want the frontend to access the token.
                */
                return new ServiceResponse<string?>
                {
                    Data = null,
                    Success = login.Success,
                    Message = login.Message,
                };
            }
    
            [HttpPost("sign-in-deliverer-with-phone-number")]
            public async Task<ActionResult<ServiceResponse<string?>>> LoginDelivererWithPhoneNumber(LoginDelivererWihPhoneNumber request)
            {
                // We will try to log the deliverer
                var login = await _authenticationService.LoginDelivererWithPhoneNumber(request);
    
                //if the deliverer is logged succesfully, we create a cookie that contains the token of the login
                if (login.Success && login.Data != null)
                {
                    Response.Cookies.Append("delivererLoginJwt", login.Data, new CookieOptions
                    {
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        HttpOnly = true, //This means that the frontend can only get it but cannot access/modify it. 
                        Expires = request.RemenberMe ? DateTimeOffset.Now.AddYears(1) : DateTimeOffset.Now.AddMinutes(30)
                    });
                }
    
                /*
                 * Finally we will return a service response to inform if the login was successful or not(if not why)
                 * We return a Service Response with a null data because we don't want the frontend to access the token.
                */
                return new ServiceResponse<string?>
                {
                    Data = null,
                    Success = login.Success,
                    Message = login.Message,
                };
            }
    
            [HttpGet("get-logged-client")]
            public async Task<ActionResult<ServiceResponse<GetUserDTO?>>> GetLoggedClient()
            {
                try
                {
                    var clientLoginJwtFromCookies = Request.Cookies["clientLoginJwt"];
    
                    var validatedClientLoginJwt = _jwtService.Verify(clientLoginJwtFromCookies);
    
                    int userId = int.Parse(validatedClientLoginJwt.Issuer);
    
                    var serviceResponse = await _authenticationService.GetUserById(userId);
    
                    if (serviceResponse.Data == null)
                    {
                        serviceResponse.Success = false;
                        serviceResponse.Message = "INVALID_TOKEN";
                    }
    
                    return serviceResponse;
                }
                catch (Exception _)
                {
                    return new ServiceResponse<GetUserDTO?>
                    {
                        Data = null,
                        Success = false,
                        Message = "INVALID_TOKEN"
                    };
                }
    
            }
    
            [HttpGet("get-logged-deliverer")]
            public async Task<ActionResult<ServiceResponse<GetUserDTO?>>> GetLoggedDeliverer()
            {
                try
                {
                    var delivererLoginJwtFromCookies = Request.Cookies["delivererLoginJwt"];
    
                    var validatedDelivererLoginJwt = _jwtService.Verify(delivererLoginJwtFromCookies);
    
                    int userId = int.Parse(validatedDelivererLoginJwt.Issuer);
    
                    var serviceResponse = await _authenticationService.GetUserById(userId);
    
                    if (serviceResponse.Data == null)
                    {
                        serviceResponse.Success = false;
                        serviceResponse.Message = "INVALID_TOKEN";
                    }
    
                    return serviceResponse;
                }
                catch (Exception _)
                {
                    return new ServiceResponse<GetUserDTO?>
                    {
                        Data = null,
                        Success = false,
                        Message = "INVALID_TOKEN"
                    };
                }
    
            }
    
            //Admins
            [HttpPost("admins/sign-in")]
            public async Task<ActionResult<ServiceResponse<string?>>> LoginAdmin(LoginAdminDTO request)
            {
                //We will try to log the user
                var login = await _authenticationService.LoginAdmin(request);
    
                //if the user is logged succesfully, we create a cookie that contains the token of the login
                if (login.Success && login.Data != null)
                {
                    Response.Cookies.Append("adminLoginJwt", login.Data, new CookieOptions
                    {
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        HttpOnly = true, //This means that the frontend can only get it but cannot access/modify it. 
                        Expires = DateTimeOffset.Now.AddDays(1),
                    });
                }
    
                /*
                 * Finally we will return a service response to inform if the login was successful or not(if not why)
                 * We return a Service Response with a null data because we don't want the frontend to access the token.
                */
                return new ServiceResponse<string?>
                {
                    Data = null,
                    Success = login.Success,
                    Message = login.Message,
                };
            }
    
    
            [HttpGet("admins/get-logged-admin")]
            public async Task<ActionResult<ServiceResponse<GetUserDTO?>>> GetLoggedAdmin()
            {
                try
                {
                    var adminLoginJwtFromCookies = Request.Cookies["adminLoginJwt"];
    
                    var validatedAdminLoginJwt = _jwtService.Verify(adminLoginJwtFromCookies);
    
                    int userId = int.Parse(validatedAdminLoginJwt.Issuer);
    
                    var serviceResponse = await _authenticationService.GetUserById(userId);
    
                    if (serviceResponse.Data == null)
                    {
                        serviceResponse.Success = false;
                        serviceResponse.Message = "INVALID_TOKEN";
                    }
    
                    return serviceResponse;
                }
                catch (Exception _)
                {
                    return new ServiceResponse<GetUserDTO?>
                    {
                        Data = null,
                        Success = false,
                        Message = "INVALID_TOKEN"
                    };
                }
            }
    
    
    
            //Admins & Clients
            [HttpPost("verify-email")]
            public async Task<ActionResult<ServiceResponse<string?>>> VerifyEmail(string token)
            {
                return await _authenticationService.VerifyEmail(token);
            }
    
            [HttpPost("recover-password-with-email")]
            public async Task<ActionResult<ServiceResponse<string?>>> RecoverPasswordWithEmail(string email)
            {
                var response = await _authenticationService.RecoverPasswordWithEmail(email);
                if (response.Success)
                {
                    var emailVerificationUrl = "http://localhost:3000/reset-password/" + response.Data;
                    var emailBody = "Pour créer un nouveau mot de passe<br /> <a href=\"#URL#\"> Cliquer ici</a> <br/><br/> ***NOTEZ-BIEN: VOUS N'AVEZ QUE 24 HEURES POUR CREER UN NOUVEAU MOT DE PASSE, SINON VOUS ALLEZ DEVOIR REPRENDRE LE PROCESSUS DE CHANGEMET DE MOT DE PASSE***";
                    emailBody = emailBody.Replace("#URL#", System.Text.Encodings.Web.HtmlEncoder.Default.Encode(emailVerificationUrl));
                    
                    /* Ancienne version Tiamshop 1.0 :
                    var emailResponse = await _emailService.SendEmail(request.Email,  "Tiamshop, confirmation de la création de compte", emailBody);
                    return emailResponse;*/

                    //Nouvelle Version Tiamshop 2.0 : (On utilise RestSharp pour faire appel a l'api du microservice qui s'occupe des notifications mail, sms ...)
                    RestClient client = new RestClient("https:/tiamshop.azurewebsites.net/api/notifications/send-email");
                    
                    var sendEmailRequest = new RestRequest();
                    sendEmailRequest.AddParameter("from", "Tiamshop");
                    sendEmailRequest.AddParameter("to", email);
                    sendEmailRequest.AddParameter("subject", "Tiamshop, création d'un nouveau mot de passe.");
                    sendEmailRequest.AddParameter("html", "<html>" + emailBody + "</html>");
                    sendEmailRequest.Method = Method.Post;

                    var emailResponse = client.Execute(sendEmailRequest);

                    if (emailResponse.IsSuccessful)
                    {
                        return new ServiceResponse<string?>
                        {
                            Data = null,
                            Success = true,
                            Message = "EMAIL_SENT_SUCCESSFULLY"
                        };
                    }
                    else
                    {
                        return new ServiceResponse<string?>
                        {
                            Data = null,
                            Success = false,
                            Message = emailResponse.Content
                        };
                    }
                }
                else
                {
                    return response;
                }
            }
    
            [HttpPost("recover-password-with-phone-number")]
            public async Task<ActionResult<ServiceResponse<string?>>> RecoverPasswordWithPhoneNumber(string phoneNumber)
            {
                var response = await _authenticationService.RecoverPasswordWithPhoneNumber(phoneNumber);
                if (response.Success)
                {
                    var getUser = await _authenticationService.GetUserByPhoneNumber(phoneNumber);
                    var user = getUser.Data;
    
                    var emailVerificationUrl = "http://localhost:3000/reset-password/" + response.Data;
                    var emailBody = "Pour créer un nouveau mot de passe<br /> <a href=\"#URL#\"> Cliquer ici</a> <br/><br/> ***NOTEZ-BIEN: VOUS N'AVEZ QUE 24 HEURES POUR CREER UN NOUVEAU MOT DE PASSE, SINON VOUS ALLEZ DEVOIR REPRENDRE LE PROCESSUS DE CHANGEMET DE MOT DE PASSE***";
                    emailBody = emailBody.Replace("#URL#", System.Text.Encodings.Web.HtmlEncoder.Default.Encode(emailVerificationUrl));
                    
                    /* Ancienne version Tiamshop 1.0 :
                    var emailResponse = await _emailService.SendEmail(request.Email,  "Tiamshop, confirmation de la création de compte", emailBody);
                    return emailResponse;*/

                    //Nouvelle Version Tiamshop 2.0 : (On utilise RestSharp pour faire appel a l'api du microservice qui s'occupe des notifications mail, sms ...)
                    RestClient client = new RestClient("https:/tiamshop.azurewebsites.net/api/notifications/send-email");
                    
                    var sendEmailRequest = new RestRequest();
                    sendEmailRequest.AddParameter("from", "Tiamshop");
                    sendEmailRequest.AddParameter("to", user.Email);
                    sendEmailRequest.AddParameter("subject", "Tiamshop, création d'un nouveau mot de passe.");
                    sendEmailRequest.AddParameter("html", "<html>" + emailBody + "</html>");
                    sendEmailRequest.Method = Method.Post;

                    var emailResponse = client.Execute(sendEmailRequest);

                    if (emailResponse.IsSuccessful)
                    {
                        return new ServiceResponse<string?>
                        {
                            Data = null,
                            Success = true,
                            Message = "EMAIL_SENT_SUCCESSFULLY"
                        };
                    }
                    else
                    {
                        return new ServiceResponse<string?>
                        {
                            Data = null,
                            Success = false,
                            Message = emailResponse.Content
                        };
                    }
                }
                else
                {
                    return response;
                }
            }
    
            [HttpPost("reset-password")]
            public async Task<ActionResult<ServiceResponse<string?>>> ResetPassword(ResetPasswordDTO request)
            {
                return await _authenticationService.ResetPassword(request);
            }
    
            [HttpPost("send-verification-email")]
            public async Task<ActionResult<ServiceResponse<string?>>> SendVerificationEmail(SendVerificationEmailDTO request)
            {
                return Ok(new ServiceResponse<string>());
            }
    
            [HttpPost("logout")]
            public ActionResult<ServiceResponse<string?>> Logout()
            {
                if (Request.Cookies["clientLoginJwt"] != null)
                {
                    Response.Cookies.Delete("clientLoginJwt", new CookieOptions
                    {
                        HttpOnly = true,
                        SameSite = SameSiteMode.None,
                        Secure = true,
                    });
                    return (new ServiceResponse<string?>
                    {
                        Data = null,
                        Success = true,
                        Message = "CLIENT_LOGGED_OUT_SUCCESSFULLY"
                    });
                }
                else
                {
                    return (new ServiceResponse<string?>
                    {
                        Data = null,
                        Success = false,
                        Message = "LOG_OUT_FAILED"
                    });
                }
            }
    
            [HttpPost("delivererlogout")]
            public ActionResult<ServiceResponse<string?>> LogoutDeliverer()
            {
                if (Request.Cookies["delivererLoginJwt"] != null)
                {
                    Response.Cookies.Delete("delivererLoginJwt", new CookieOptions
                    {
                        HttpOnly = true,
                        SameSite = SameSiteMode.None,
                        Secure = true,
                    });
                    return (new ServiceResponse<string?>
                    {
                        Data = null,
                        Success = true,
                        Message = "CLIENT_LOGGED_OUT_SUCCESSFULLY"
                    });
                }
                else
                {
                    return (new ServiceResponse<string?>
                    {
                        Data = null,
                        Success = false,
                        Message = "LOG_OUT_FAILED"
                    });
                }
            }
    
            [HttpPost("admins/logout")]
            public ActionResult<ServiceResponse<string?>> AdminLogout()
            {
                if (Request.Cookies["adminLoginJwt"] != null)
                {
                    Response.Cookies.Delete("adminLoginJwt", new CookieOptions
                    {
                        HttpOnly = true,
                        SameSite = SameSiteMode.None,
                        Secure = true,
                    });
                    return (new ServiceResponse<string?>
                    {
                        Data = null,
                        Success = true,
                        Message = "ADMIN_LOGGED_OUT_SUCCESSFULLY"
                    });
                }
                else
                {
                    return (new ServiceResponse<string?>
                    {
                        Data = null,
                        Success = false,
                        Message = "LOG_OUT_FAILED"
                    });
                }
            }
}