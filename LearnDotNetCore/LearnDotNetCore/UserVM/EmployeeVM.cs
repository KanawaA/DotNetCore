using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.UserVM
{
    public class EmployeeVM
    {
        public string EmpId { get; set; }
        public string Username { get; set; }
        public string Address { get; set; }
        public string Phone { get; set; }

        public DateTimeOffset CreateDate { get; set; }
        public DateTimeOffset UpdateDate { get; set; }
        public DateTimeOffset DeleteData { get; set; }
        public bool isDelete { get; set; }
    }
}
