using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using LearnDotNetCore.Context;
using LearnDotNetCore.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly MyContext _context;
        public UsersController(MyContext myContext)
        {
            _context = myContext;
        }

        // GET api/values
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
            //return _context.Users.Include(r => r.roles);
            //return await _context.Users.ToListAsync<User>();
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
            userVM.RoleName = "Sales";
            var user = new User();
            var roleuser = new RoleUser();
            var role = _context.Roles.Where(r => r.Name == userVM.RoleName).FirstOrDefault();
            user.UserName = userVM.UserName;
            user.Email = userVM.Email;
            user.EmailConfirmed = false;
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(userVM.Password);
            user.PhoneNumber = userVM.Phone;
            user.PhoneNumberConfirmed = false;
            user.TwoFactorEnabled = false;
            user.LockoutEnabled = false;
            user.AccessFailedCount = 0;
            roleuser.Role = role;
            roleuser.User = user;
            _context.RoleUsers.AddAsync(roleuser);
            _context.Users.AddAsync(user);
            _context.SaveChanges();
            return Ok("Successfully Created");
            //return data;
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
                    var user = new UserVM();
                    user.Id = getUserRole.User.Id;
                    user.UserName = getUserRole.User.UserName;
                    user.Email = getUserRole.User.Email;
                    user.Password = getUserRole.User.PasswordHash;
                    user.Phone = getUserRole.User.PhoneNumber;
                    user.RoleName = getUserRole.Role.Name;
                    return StatusCode(200, user);
                }
            }
            return BadRequest(500);
        }
    }
}
