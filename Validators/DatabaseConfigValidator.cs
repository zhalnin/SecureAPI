using FluentValidation;
using SecureAPI.Configurations;

namespace SecureAPI.Validators
{
    public sealed class DatabaseConfigValidator : AbstractValidator<DatabaseConfig>
    {
        public DatabaseConfigValidator()
        {
            RuleFor(x => x.TimeoutTime).NotEmpty()
                .InclusiveBetween(0, 30)
                .WithMessage("Should be range");
        }
    }
}
