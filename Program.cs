using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureAPI.Configurations;
using SecureAPI.Data;
using FluentValidation;
using SecureAPI.ServiceCollectionExtensions;

var builder = WebApplication.CreateBuilder(args);

var sqlConBuilder = new SqlConnectionStringBuilder
{
    ConnectionString = builder.Configuration.GetConnectionString("SQLDbConnection"),
    UserID = builder.Configuration["DBUserId"],
    Password = builder.Configuration["DBPassword"],
    InitialCatalog = builder.Configuration["DBInitialCatalog"],
    DataSource = builder.Configuration["DBDataSource"],
    ConnectTimeout = 60,
    Encrypt = false
};

builder.Services.AddDbContext<AppDbContext>(opt =>
{
    opt.UseSqlServer(sqlConBuilder.ConnectionString);
});

builder.Services.AddOptionsWithFluentValidation<JwtConfig>(nameof(JwtConfig));
builder.Services.AddOptionsWithFluentValidation<DatabaseConfig>(nameof(DatabaseConfig));

var key = Encoding.ASCII.GetBytes(builder.Configuration.GetValue<string>("JwtConfig:Secret") ?? string.Empty);
var tokenValidationParameter = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false, //for DEV
    ValidateAudience = false,
    RequireExpirationTime = false,
    ValidateLifetime = true
};

builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(jwt =>
{
    jwt.SaveToken = true;
    jwt.TokenValidationParameters = tokenValidationParameter;
});

builder.Services.AddSingleton(tokenValidationParameter);
builder.Services.AddDefaultIdentity<IdentityUser>(opt => opt.SignIn.RequireConfirmedAccount = false)
.AddEntityFrameworkStores<AppDbContext>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddValidatorsFromAssembly(typeof(Program).Assembly);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();