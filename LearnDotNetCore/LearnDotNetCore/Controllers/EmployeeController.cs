using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LearnDotNetCore.Context;
using LearnDotNetCore.UserVM;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LearnDotNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeeController : ControllerBase
    {
        public EmployeeController(MyContext myContext)
        {
            _context = myContext;
        }
        private readonly MyContext _context;
        // GET api/values
        [HttpGet]
        public async Task<List<EmployeeVM>> GetAll()
        {
            List<EmployeeVM> list = new List<EmployeeVM>();
            //var user = new UserVM();
            var getData = await _context.Employees.Include("User").Where (x=> x.IsDelete == false).ToListAsync();
            if (getData.Count == 0)
            {
                return null;
            }
            foreach (var item in getData)
            {
                var emp = new EmployeeVM()
                {
                    EmpId = item.User.Id,
                    Username = item.User.UserName,
                    Address = item.Adress,
                    Phone = item.User.PhoneNumber,
                    CreateDate = item.CreateTime,
                    UpdateDate = item.UpdateTime
                };
                list.Add(emp);
            }
            return list;
        }

        //[Authorize]
        [HttpGet("{id}")]
        public EmployeeVM GetID(string id)
        {
            var getData = _context.Employees.Include("User").SingleOrDefault(x => x.EmpId == id);
            if (getData == null || getData.User == null)
            {
                return null;
            }
            var emp = new EmployeeVM()
            {
                EmpId = getData.User.Id,
                Username = getData.User.UserName,
                Address = getData.Adress,
                Phone = getData.User.PhoneNumber,
                CreateDate = getData.CreateTime,
                UpdateDate = getData.UpdateTime
            };
            return emp;
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            if (ModelState.IsValid)
            {
                var getData = _context.Employees.Include("User").SingleOrDefault(x => x.EmpId == id);
                if (getData == null)
                {
                    return BadRequest("Not Successfully");
                }
                getData.DeleteTime = DateTimeOffset.Now;
                getData.IsDelete = true;

                //_context.Employees.Update(getData);
                _context.Entry(getData).State = EntityState.Modified;
                _context.SaveChanges();
                return Ok("Successfully Deleted");
            }
            return BadRequest("Not Successfully");
        }
    }
}