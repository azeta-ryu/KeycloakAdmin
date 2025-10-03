using KeycloakAdmin;
using KeycloakAdmin.Endpoints;
using Scalar.AspNetCore;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

builder.Services.AddOpenApi();
builder.Services.AddKeycloakHttpClient(o =>
{
    o.Host = "https://auth.dev.biggie.com.py";
    o.Realm = "master";
    o.ClientId = "admin-cli";
    o.Flow = KeycloakAuthFlow.Password;
    o.Username = "admin";
    o.Password = "admin";
    o.FailFastOnStartup = true;
    o.LogRequestBody = true;
    o.LogResponseBody = true;
    o.MaxBodyLogBytes = 8192;
});

var app = builder.Build();
app.MapOpenApi();
app.MapScalarApiReference();
app.MapKeycloakUserBulkEndpoints();

app.Run();