using System.Collections.Generic;
using Demo1.Models;

namespace Demo1.Infrastructure
{
    public static class UserRepository
    {
        public static List<AppUser> Users;
        static UserRepository()
        {
            Users = new List<AppUser>();
        }
    }
}