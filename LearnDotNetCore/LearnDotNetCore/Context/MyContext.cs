using LearnDotNetCore.Model;
using LearnDotNetCore.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace LearnDotNetCore.Context
{
    public class MyContext : DbContext
    {
        public MyContext(DbContextOptions<MyContext> options) : base(options)
        {
        }
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<RoleUser> RoleUsers { get; set; }
        public DbSet<Department> Depatments { get; set; }
        public DbSet<Division> Divisions { get; set; }
        public DbSet<Employee> Employees { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        { 
            modelBuilder.Entity<Employee>().HasKey(sc => sc.EmpId);

            modelBuilder.Entity<Employee>()
                        .HasOne<User>(e => e.User)  
                        .WithOne(u => u.Employee)
                        .HasForeignKey<Employee>(u => u.EmpId);  
        }
    }
}
