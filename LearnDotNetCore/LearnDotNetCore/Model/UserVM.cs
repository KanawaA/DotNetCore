using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Model
{
    public class UserVM
    {

        public string Id { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Phone { get; set; }
        public string RoleName { get; set; }
        public string VerifyCode { get; set; }

        public UserVM(UserVM user)
        {
            this.Id = user.Id;
            this.Email = user.Email;
            this.UserName = user.UserName;
            this.Password = user.Password;
            this.Phone = user.Phone;


        }

        public UserVM()
        {
        }
    }
}
