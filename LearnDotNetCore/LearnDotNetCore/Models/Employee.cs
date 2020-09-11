using LearnDotNetCore.Model;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Models
{
    [Table ("TB_M_Employee")]
    public class Employee
    {
        public string EmpId { get; set; }
        public string Adress { get; set; }
        public DateTimeOffset CreateTime { get; set; }
        public DateTimeOffset UpdateTime { get; set; }
        public DateTimeOffset DeleteTime { get; set; }
        public bool IsDelete { get; set; }

        public User User { get; set; }
    }
}
