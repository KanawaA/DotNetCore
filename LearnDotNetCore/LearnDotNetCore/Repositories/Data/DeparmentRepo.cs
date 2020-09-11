using LearnDotNetCore.Context;
using LearnDotNetCore.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Repositories.Data
{
    public class DeparmentRepo : GeneralRepository<Department, MyContext>
    {
        public DeparmentRepo(MyContext context) : base(context)
        {

        }
    }
}
