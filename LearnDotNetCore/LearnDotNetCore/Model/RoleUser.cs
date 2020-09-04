using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Model
{
    [Table ("TB_M_RoleUser")]
    public class RoleUser : IdentityUserRole<string>
    {
        public string Id { get; set; }
        public User User { get; set; }
        public Role Role { get; set; }
    }
}
