using BC = BCrypt.Net.BCrypt;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;
using System.Net.Http.Headers;
using LearnDotNetCore.Model;
using System.IdentityModel.Tokens.Jwt;

namespace Web.Controllers
{
    public class AuthController : Controller
    {
        readonly HttpClient client = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:44316/api/")
        };

        [Route("login")]
        public IActionResult Login()
        {
            return View("~/Views/Auth/Login.cshtml");
        }

        [Route("register")]
        public IActionResult Register()
        {
            return View();
        }

        [Route("logout")]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return Redirect("/login");
        }

        [Route("verify")]
        public IActionResult Verify()
        {
            return View();
        }

        [Route("notfound")]
        public IActionResult Notfound()
        {
            return View();
        }

        [Route("validate")]
        public IActionResult Validate(UserVM userVM)
        {
            //    var json = JsonConvert.SerializeObject(userVM);
            //    var buffer = System.Text.Encoding.UTF8.GetBytes(json);
            //    var byteContent = new ByteArrayContent(buffer);
            //    byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            //    if (userVM.UserName == null)
            //    { // Login
            //        HttpResponseMessage result = null;
            //        if (userVM.VerifyCode != null)
            //        {
            //            result = client.PostAsync("users/code/", byteContent).Result;
            //        }
            //        else if (userVM.VerifyCode == null)
            //        {
            //            result = client.PostAsync("users/login/", byteContent).Result;
            //        }

            //        if (result.IsSuccessStatusCode)
            //        {
            //            var data = result.Content.ReadAsStringAsync().Result;
            //            if (data != null)
            //            {
            //                HttpContext.Session.SetString("token", "Bearer " + data);
            //                var handler = new JwtSecurityTokenHandler();
            //                var tokenS = handler.ReadJwtToken(data);
            //                var jwtPayloadSer = JsonConvert.SerializeObject(tokenS.Payload.ToDictionary(x => x.Key, x => x.Value));
            //                var jwtPayloadDes = JsonConvert.DeserializeObject(jwtPayloadSer).ToString();
            //                var account = JsonConvert.DeserializeObject<UserVM>(jwtPayloadSer);

            //                if (!account.VerifyCode.Equals(""))
            //                {
            //                    return Json(new { status = true, msg = "VerifyCode" });
            //                }
            //                else if (account.RoleName != null)
            //                {
            //                    HttpContext.Session.SetString("id", account.Id);
            //                    HttpContext.Session.SetString("uname", account.UserName);
            //                    HttpContext.Session.SetString("email", account.Email);
            //                    HttpContext.Session.SetString("lvl", account.RoleName);
            //                    if (account.RoleName == "Admin")
            //                    {
            //                        return Json(new { status = true, msg = "Login Successfully !" });
            //                        //return View("~/Views/Auth/verify.cshtml");
            //                    }
            //                    return Json(new { status = true, msg = "Login Successfully !" });
            //                }
            //                return Json(new { status = false, msg = "You Don't Have Permissions! Please Contact Administrator" });
            //            }
            //            return Json(new { status = false, msg = result.Content.ReadAsStringAsync().Result });
            //        }
            //        return Json(new { status = false, msg = result.Content.ReadAsStringAsync().Result });
            //    }
            //    else if (userVM.UserName != null)
            //    { // Register
            //        var result = client.PostAsync("users/register/", byteContent).Result;
            //        if (result.IsSuccessStatusCode)
            //        {
            //            return Json(new { status = true, code = result, msg = "Register Success! " });
            //        }
            //        return Json(new { status = false, msg = result.Content.ReadAsStringAsync().Result });
            //    }
            //    return Redirect("/login");
            //}


            if (userVM.UserName == null)
            { //login
                var jsonUserVM = JsonConvert.SerializeObject(userVM);
                var buffer = System.Text.Encoding.UTF8.GetBytes(jsonUserVM);
                var byteContent = new ByteArrayContent(buffer);
                byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                var resTask = client.PostAsync("users/login/", byteContent);
                resTask.Wait();
                var result = resTask.Result;
                if (result.IsSuccessStatusCode)
                {
                    var data = result.Content.ReadAsStringAsync().Result;
                    if (data != null)
                    {
                        HttpContext.Session.SetString("token", "Bearer " + data);                       //tambahan
                        var handler = new JwtSecurityTokenHandler();
                        var tokenS = handler.ReadJwtToken(data);

                        //var user = new UserVM();
                        //user.Id = tokenS.Claims.First(claim => claim.Type == "Id").Value;
                        //user.UserName = tokenS.Claims.First(claim => claim.Type == "Username").Value;
                        //user.Email = tokenS.Claims.First(claim => claim.Type == "Email").Value;
                        //user.RoleName = tokenS.Claims.First(claim => claim.Type == "RoleName").Value;

                        var jwtPayloadSer = JsonConvert.SerializeObject(tokenS.Payload.ToDictionary(x => x.Key, x => x.Value));         //tambahan
                        var jwtPayloadDes = JsonConvert.DeserializeObject(jwtPayloadSer).ToString();
                        var user = JsonConvert.DeserializeObject<UserVM>(jwtPayloadSer);

                        if (user.VerifyCode != null)
                        {
                            if (userVM.VerifyCode != user.VerifyCode)
                            {
                                return Json(new { status = true, msg = "Check your Code" });
                            }
                        }
                        else if (user.RoleName == "Admin" || user.RoleName == "Sales")
                        {
                            HttpContext.Session.SetString("id", user.Id);
                            HttpContext.Session.SetString("uname", user.UserName);
                            HttpContext.Session.SetString("email", user.Email);
                            HttpContext.Session.SetString("lvl", user.RoleName);
                            if (user.RoleName == "Admin")
                            {
                                return Json(new { status = true, msg = "Login Successfully !", acc = "Admin" });
                            }
                            else
                            {
                                return Json(new { status = true, msg = "Login Successfully !", acc = "Sales" });
                            }
                        }
                        else
                        {
                            return Json(new { status = false, msg = "Invalid Username or Password!" });
                        }
                    }
                    else
                    {
                        return Json(new { status = false, msg = "Username Not Found!" });
                    }
                }
                else
                {
                    //return RedirectToAction("Login","Auth");
                    return Json(new { status = false, msg = "Something Wrong!" });
                }
            }
            else if (userVM.UserName != null)
            { // Register
                var json = JsonConvert.SerializeObject(userVM);
                var buffer = System.Text.Encoding.UTF8.GetBytes(json);
                var byteContent = new ByteArrayContent(buffer);
                byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                var result = client.PostAsync("users/", byteContent).Result;
                if (result.IsSuccessStatusCode)
                {
                    return Json(new { status = true, code = result, msg = "Register Success! " });
                }
                else
                {
                    return Json(new { status = false, msg = "Something Wrong!" });
                }
            }
            return Redirect("/login");
        }

        [Route("getjwt")]
        public IActionResult GetName()
        {
            var stream = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJJZCI6ImRiM2VhZmIxLTkyMWUtNDdmYS1hOGFiLTIwNDYxMzkxM2FlMCIsIlVzZXJuYW1lIjoiUmlmcXkiLCJFbWFpbCI6Im11aGFtbWFkcmlmcWkwQGdtYWlsLmNvbSIsIlJvbGVOYW1lIjoiU2FsZXMiLCJleHAiOjE1OTk1NDY0MTYsImlzcyI6IkludmVudG9yeUF1dGhlbnRpY2F0aW9uU2VydmVyIiwiYXVkIjoiSW52ZW50b3J5c2VydmljZVBvc3RtYW50Q2xpZW50In0.ziIjgvqJdH17w4HwHGzvXyZTUz41S06i0xHWGxAnY2M";
            var handler = new JwtSecurityTokenHandler();
            var tokenS = handler.ReadJwtToken(stream);

            //var user = new UserVM()                                                                 //dipake
            //{
            //    Id = tokenS.Claims.First(claim => claim.Type == "Id").Value,
            //    UserName = tokenS.Claims.First(claim => claim.Type == "Username").Value,
            //    Email = tokenS.Claims.First(claim => claim.Type == "Email").Value,
            //    RoleName = tokenS.Claims.First(claim => claim.Type == "RoleName").Value,
            //};

            //var usrVm = new UserVM();                                                               //dipake
            ////return Json(user);
            //return Json(tokenS.Payload);

            //var jwtPayloadSer = JsonConvert.SerializeObject(tokenS.Payload.ToDictionary(x => x.Key, x => x.Value));
            //var jwtPayloadDes = JsonConvert.DeserializeObject(jwtPayloadSer).ToString();
            //var account = JsonConvert.DeserializeObject<UserVM>(jwtPayloadSer);

            // Output the whole thing to pretty Json object formatted.
            //return Json(new { account.Id, account.UserName, account.Email, account.RoleName, account.VerifyCode });

            var jwtPayloadSer = JsonConvert.SerializeObject(tokenS.Payload.ToDictionary(x => x.Key, x => x.Value));
            var jwtPayloadDes = JsonConvert.DeserializeObject(jwtPayloadSer).ToString();
            var account = JsonConvert.DeserializeObject<UserVM>(jwtPayloadSer);

            // Output the whole thing to pretty Json object formatted.
            return Json(new { account.Id, account.UserName, account.Email, account.RoleName, account.VerifyCode });
        }
    }
}
