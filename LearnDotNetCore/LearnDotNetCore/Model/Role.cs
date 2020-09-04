using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Model
{
    [Table("TB_M_Role")]
    public class Role : IdentityRole
    {
    }
}
