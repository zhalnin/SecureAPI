using Microsoft.Extensions.Options;
using SecureAPI.Validators;

namespace SecureAPI.OptionsBuilderExtensions
{
    public static class OptionsBuilderExtensions
    {
        public static OptionsBuilder<TOptions> ValidateFluentValidation<TOptions>(this OptionsBuilder<TOptions> builder)
            where TOptions : class
        {
            builder.Services.AddSingleton<IValidateOptions<TOptions>>(
                serviceProvider => new FluentValidateOptions<TOptions>(serviceProvider, builder.Name));
            return builder;
        }
    }
}