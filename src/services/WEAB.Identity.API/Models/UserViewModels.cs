using System.ComponentModel.DataAnnotations;

namespace WEAB.Identity.API.Models
{
    public class UserRegister
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [EmailAddress(ErrorMessage = "Email inválido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [StringLength(100, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres", MinimumLength = 6)]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "As senhas não conferem.")]
        public string ConfirmationPassword { get; set; }
    }

    public class UserLogin
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [EmailAddress(ErrorMessage = "Email inválido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        public string  Password { get; set; }
    }

    public class UserAnswerLogin
    {
        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }

        public TokenUser TokenUser { get; set; }

    }

    public class TokenUser
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public IEnumerable<ClaimUser> Claims { get; set; }

    }

    public class ClaimUser
    {
        public string Value { get; set; }
        public string Type { get; set; }
    }
}
