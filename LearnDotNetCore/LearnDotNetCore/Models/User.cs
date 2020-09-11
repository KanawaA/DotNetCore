using LearnDotNetCore.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Model
{
    [Table("Tb_M_User")]
    public class User : IdentityUser
    {
        internal IEnumerable<RoleUser> roleUser;

        public Employee Employee { get; internal set; }
    }
}
