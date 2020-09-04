using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using LearnDotNetCore.Context;
using LearnDotNetCore.Model;

namespace LearnDotNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RolesController : ControllerBase
    {
        private readonly MyContext _context;
        public RolesController(MyContext myContext)
        {
            _context = myContext;
        }

        [HttpGet]
        //public async Task<List<User>> GetAll()
        public List<Role> GetAll()
        {
            List<Role> list = new List<Role>();
            foreach (var item in _context.Roles)
            {
                list.Add(item);
            }
            return list;
        }

        [HttpGet("{id}")]
        public Role GetID(int id)
        {
            return _context.Roles.Find(id);
        }

        [HttpPost]
        public IActionResult Create(Role role)
        {
            var roles = new Role();
            roles.Name = role.Name;
            _context.Roles.AddAsync(roles);
            _context.SaveChanges();
            return Ok("Successfully Created");
            //return data;
        }

        [HttpPut("{id}")]
        public IActionResult Update(string id, Role role)
        {
            var getId = _context.Roles.Find(id);
            getId.Id = role.Id;
            getId.Name = role.Name;
            _context.SaveChanges();
            return Ok("Successfully Update");
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            var getId = _context.Roles.Find(id);
            _context.Roles.Remove(getId);
            _context.SaveChanges();
            return Ok("Successfully Delete");
        }
    }
}