using LearnDotNetCore.Bases;
using LearnDotNetCore.Model;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Models
{
    [Table ("TB_M_Division")]
    public class Division : BaseModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public int DepartmentId { get; set; }
        public DateTimeOffset CreateDate { get; set; }
        public DateTimeOffset DeleteDate { get; set; }
        public DateTimeOffset UpdateDate { get; set; }
        public bool isDelete { get; set; }

        [ForeignKey("DepartmentId")]
        public Department department { get; set; }
    }
}
