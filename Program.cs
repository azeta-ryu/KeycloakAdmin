using KeycloakAdmin;
using KeycloakAdmin.Endpoints;
using Scalar.AspNetCore;

var builder = WebApplication.CreateSlimBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

builder.Services.AddOpenApi();
builder.Services.AddKeycloakHttpClient(o =>
{
    builder.Configuration.GetSection("Keycloak").Bind(o);
});

var app = builder.Build();
app.MapOpenApi();
app.MapScalarApiReference();
app.MapGet("/", () => Results.Redirect("/scalar"));
app.MapKeycloakEndpoints();

app.Run();