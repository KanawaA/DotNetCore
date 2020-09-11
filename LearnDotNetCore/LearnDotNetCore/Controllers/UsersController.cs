using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using LearnDotNetCore.Context;
using LearnDotNetCore.Migrations;
using LearnDotNetCore.Model;
using LearnDotNetCore.Models;
using LearnDotNetCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly MyContext _context;
        SmtpClient client = new SmtpClient();
        AttrEmail attrEmail = new AttrEmail();
        RandomDigit randDig = new RandomDigit();
        public IConfiguration _configuration;

        public UsersController(MyContext myContext, IConfiguration configuration, IConfiguration config)
        {
            _context = myContext;
            _configuration = configuration;
            _configuration = config;
        }

        // GET api/values
        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet]
        //public async Task<List<User>> GetAll()
        public List<UserVM> GetAll()
        {
            List<UserVM> list = new List<UserVM>();
            foreach (var item in _context.Users)
            {
                var role = _context.RoleUsers.Where(ru => ru.UserId == item.Id).FirstOrDefault();
                var roler = _context.Roles.Where(r => r.Id == role.RoleId).FirstOrDefault();
                UserVM user = new UserVM()
                {
                    Id = item.Id,
                    UserName = item.UserName,
                    Email = item.Email,
                    Password = item.PasswordHash,
                    Phone = item.PhoneNumber,
                    RoleName = roler.Name
                };
                list.Add(user);
            }
            return list;
        }

        [HttpGet("{id}")]
        public UserVM GetID(string id)
        {
            var getId = _context.Users.Find(id);
            UserVM user = new UserVM()
            {
                Id = getId.Id,
                UserName = getId.UserName,
                Email = getId.Email,
                Password = getId.PasswordHash,
                Phone = getId.PhoneNumber
            };
            return user;
        }

        [HttpPost]
        public IActionResult Create(UserVM userVM)
        {
            if (ModelState.IsValid)
            {
                client.Port = 587;
                client.Host = "smtp.gmail.com";
                client.EnableSsl = true;
                client.Timeout = 10000;
                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                client.UseDefaultCredentials = false;
                client.Credentials = new NetworkCredential(attrEmail.mail, attrEmail.pass);

                var code = randDig.GenerateRandom();
                var fill = "Hi " + userVM.UserName + "\n\n"
                          + "Try this Password to get into reset password: \n"
                          + code
                          + "\n\nThank You";

                MailMessage mm = new MailMessage("donotreply@domain.com", userVM.Email, "Create Email", fill);
                mm.BodyEncoding = UTF8Encoding.UTF8;
                mm.DeliveryNotificationOptions = DeliveryNotificationOptions.OnFailure;
                client.Send(mm);

                var user = new User
                {
                    UserName = userVM.UserName,
                    Email = userVM.Email,
                    SecurityStamp = code,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(userVM.Password),
                    PhoneNumber = userVM.Phone,
                    EmailConfirmed = false,
                    PhoneNumberConfirmed = false,
                    TwoFactorEnabled = false,
                    LockoutEnabled = false,
                    AccessFailedCount = 0
                };
                _context.Users.Add(user);
                var uRole = new RoleUser
                {
                    UserId = user.Id,
                    RoleId = "2"
                };
                _context.RoleUsers.Add(uRole);
                var emp = new Employee
                {
                    EmpId = user.Id,
                    CreateTime = DateTimeOffset.Now,
                    IsDelete = false
                };
                _context.Employees.Add(emp);
                _context.SaveChanges();
                return Ok("Successfully Created");
            }
            return BadRequest("Register Failed");
        }

        [HttpPut("{id}")]
        public IActionResult Update(string id, UserVM userVM)
        {
            var getId = _context.Users.Find(id);
            getId.Id = userVM.Id;
            getId.UserName = userVM.UserName;
            getId.Email = userVM.Email;
            var isValid = BCrypt.Net.BCrypt.Verify(userVM.Password, getId.PasswordHash);
            if (isValid) { Ok("Failed Update"); }
            else
            {
                var hasPass = BCrypt.Net.BCrypt.HashPassword(userVM.Password, 12);
                getId.PasswordHash = hasPass;
            }

            getId.PhoneNumber = userVM.Phone;
            var data = _context.Users.Update(getId);
            _context.SaveChanges();
            return Ok("Successfully Update");
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            var getIdr = _context.RoleUsers.Where(g => g.UserId == id).FirstOrDefault();
            var getId = _context.Users.Find(id);
            _context.Users.Remove(getId);
            _context.RoleUsers.Remove(getIdr);
            _context.SaveChanges();
            return Ok("Successfully Delete");
        }

        [HttpPost]
        [Route("login")]
        public IActionResult Login(UserVM userVM)
        {
            if (ModelState.IsValid)
            {
                var getUserRole = _context.RoleUsers.Include("User").Include("Role").SingleOrDefault(x => x.User.Email == userVM.Email);
                if (getUserRole == null)
                {
                    return NotFound();
                }
                else if (userVM.Password == null || userVM.Password.Equals(""))
                {
                    return BadRequest(new { msg = "Password must filled" });
                }
                else if (!BCrypt.Net.BCrypt.Verify(userVM.Password, getUserRole.User.PasswordHash))
                {
                    return BadRequest(new { msg = "Password is Wrong" });
                }
                else
                {
                    //var user = new UserVM();
                    //user.Id = getUserRole.User.Id;
                    //user.UserName = getUserRole.User.UserName;
                    //user.Email = getUserRole.User.Email;
                    //user.Password = getUserRole.User.PasswordHash;
                    //user.Phone = getUserRole.User.PhoneNumber;
                    //user.RoleName = getUserRole.Role.Name;
                    //user.VerifyCode = getUserRole.User.SecurityStamp;
                    //if (user != null)
                    //{
                    //    var claims = new List<Claim>
                    //                {
                    //                    new Claim ("UserName", user.UserName),
                    //                    new Claim("Email", user.Email)
                    //                };

                    //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

                    //    var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                    //    var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.UtcNow.AddSeconds(30), signingCredentials: signIn);

                    //    return Ok(new JwtSecurityTokenHandler().WriteToken(token));
                    //}
                    if (getUserRole != null)
                    {
                        if (getUserRole.User.SecurityStamp != null)
                        {
                            var claims = new List<Claim> {
                                new Claim("Id", getUserRole.User.Id),
                                new Claim("Username", getUserRole.User.UserName),
                                new Claim("Email", getUserRole.User.Email),
                                new Claim("RoleName", getUserRole.Role.Name),
                                new Claim("VerifyCode", getUserRole.User.SecurityStamp)
                            };
                            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.UtcNow.AddDays(1), signingCredentials: signIn);
                            //var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.UtcNow.AddDays(1), signingCredentials: signIn);
                            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
                        }
                        else
                        {
                            var claims = new List<Claim> {
                                new Claim("Id", getUserRole.User.Id),
                                new Claim("Username", getUserRole.User.UserName),
                                new Claim("Email", getUserRole.User.Email),
                                new Claim("RoleName", getUserRole.Role.Name)
                            };
                            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, expires: DateTime.UtcNow.AddDays(1), signingCredentials: signIn);
                            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
                        }
                    }
                    return BadRequest("Invalid credentials");
                }
            }
            return BadRequest(500);
        }

        [HttpPost]
        [Route("code")]
        public IActionResult VerifyCode(UserVM userVM)
        {
            if (ModelState.IsValid)
            {
                var getUserRole = _context.RoleUsers.Include("User").Include("Role").SingleOrDefault(x => x.User.Email == userVM.Email);
                if (getUserRole == null)
                {
                    return NotFound();
                }
                else if (userVM.VerifyCode != getUserRole.User.SecurityStamp)
                {
                    return BadRequest(new { msg = "Your Code is Wrong" });
                }
                else
                {
                    //var user = new UserVM();
                    //user.Id = getUserRole.User.Id;
                    //user.Username = getUserRole.User.UserName;
                    //user.Email = getUserRole.User.Email;
                    //user.Password = getUserRole.User.PasswordHash;
                    //user.Phone = getUserRole.User.PhoneNumber;
                    //user.RoleName = getUserRole.Role.Name;
                    //return StatusCode(200, user);
                    return StatusCode(200, new
                    {
                        Username = getUserRole.User.UserName,
                        Email = getUserRole.User.Email,
                        RoleName = getUserRole.Role.Name,
                        //Email = getUserRole.User.Email,
                        //Password = getUserRole.User.PasswordHash
                    });
                }
            }
            return BadRequest(500);
        }
    }
}
