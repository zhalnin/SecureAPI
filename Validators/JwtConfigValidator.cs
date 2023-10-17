using FluentValidation;
using SecureAPI.Configurations;

namespace SecureAPI.Validators
{
    public class JwtConfigValidator : AbstractValidator<JwtConfig>
    {
        public JwtConfigValidator()
        {
            RuleFor(x => x.Secret).NotEmpty()
                .WithMessage("Should be filled")
                .MinimumLength(40)
                .WithMessage("Should be minimum 40 symbols length");
        }
    }
}
