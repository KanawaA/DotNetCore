using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LearnDotNetCore.Context;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using static LearnDotNetCore.UserVM.ChartVM;

namespace LearnDotNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ChartsController : ControllerBase
    {
        private readonly MyContext _context;
        public ChartsController(MyContext myContext)
        {
            _context = myContext;
        }
        // GET api/values
        [HttpGet]
        [Route("pie")]
        public async Task<List<PieChartVM>> GetPie()
        {
            var data1 = await _context.Divisions.Include("department")
                            .Where(x => x.isDelete == false)
                            .GroupBy(q => q.department.Name)
                            .Select(q => new PieChartVM
                            {
                                DepartmentName = q.Key,
                                total = q.Count()
                            }).ToListAsync();
            return data1;
        }
    }
}