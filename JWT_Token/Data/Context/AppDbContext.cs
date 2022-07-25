using JWT_Token.Data.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
#nullable disable

namespace JWT_Token.Data.Context
{
    public class AppDbContext : IdentityDbContext
    {
        public AppDbContext()
        { }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
            User.AddRange(new User[]
            {
                new User { Id = 1, Login = "dimaoleks", Email = "d.oleksandryuk@gmail.com", Name = "Dmytro", Password = "12345" },
                new User { Id = 2, Login = "vityok", Email = "vityaborzyi@yahoo.com", Name = "Viktor", Password = "qwerty123" },
                new User { Id = 3, Login = "andrey123", Email = "zzaa@gmail.com", Name = "Andrey", Password = "asdqwe" }
            });
        }

        public DbSet<User> User { get; set; }
    }
}
