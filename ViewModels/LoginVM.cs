using System.ComponentModel.DataAnnotations;
namespace Demo1.ViewModels
{
    public class LoginVM
    {
        public string UserName { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}