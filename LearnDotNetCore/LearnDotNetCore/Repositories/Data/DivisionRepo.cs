using LearnDotNetCore.Context;
using LearnDotNetCore.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Repositories.Data
{
    public class DivisionRepo : GeneralRepository<Division, MyContext>
    {
        MyContext _context;

        public DivisionRepo(MyContext context) : base(context)
        {
            _context = context;
        }

        public override async Task<List<Division>> Get()
        {
            var data = await _context.Divisions.Include("department").Where(x => x.isDelete == false).ToListAsync();
            return data;
        }
    }
}
