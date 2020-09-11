using LearnDotNetCore.Bases;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Model
{
    [Table ("TB_M_Department")]
    public class Department : BaseModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public DateTimeOffset CreateDate { get; set; }
        public DateTimeOffset DeleteDate { get; set; }
        public DateTimeOffset UpdateDate { get; set; }
        public bool isDelete { get; set; }

        //public Department()
        //{

        //}

        //public Department(Department department)
        //{
        //    this.Name = department.Name;
        //    this.CreateDate = DateTimeOffset.Now;
        //    this.isDelete = false;
        //}

        //public void Update(Department department)
        //{
        //    this.Name = department.Name;
        //    this.UpdateDate = DateTimeOffset.Now;
        //}

        //public void Delete(Department department)
        //{
        //    this.isDelete = true;
        //    this.DeleteDate = DateTimeOffset.Now;
        //}
    }
}
