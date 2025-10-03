using System.Net;
using System.Text.Json.Serialization;
using KeycloakAdmin.OpenApi;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KeycloakAdmin.Endpoints;

internal static class KeycloakUserBulkEndpoints
{
    public static void MapKeycloakUserBulkEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/keycloak/users");
        group.MapPost("/bulk", BulkCreate);
    }

    // Request DTO
    public sealed record Person(string NationalId, string Email, string Name, string LastName);

    // Response DTO
    public sealed record BulkCreateUserResult(
        string Username,
        string? UserId,
        bool Created,
        bool PasswordSet,
        string? Error);

    private static async Task<IResult> BulkCreate(
        [FromServices] KeycloakOpenApiClient kc,
        [FromServices] IOptions<KeycloakClientOptions> opts,
        [FromBody] Person[] people,
        CancellationToken ct)
    {
        if (people is null || people.Length == 0)
            return Results.BadRequest("Body must be a non-empty array of Person.");

        var realm = opts.Value.Realm;
        var results = new List<BulkCreateUserResult>(people.Length);

        foreach (var p in people)
        {
            var username = p.NationalId?.Trim();
            if (string.IsNullOrWhiteSpace(username))
            {
                results.Add(new(username ?? "", null, false, false, "NationalId is required"));
                continue;
            }

            string? userId = null;
            var created = false;
            var passwordSet = false;

            try
            {
                // 1) Create the user
                var user = new UserRepresentation
                {
                    Username = username,
                    Email = p.Email,
                    FirstName = p.Name,
                    LastName = p.LastName,
                    Enabled = true
                };

                await kc.UsersPOSTAsync(user, realm, ct); // POST /admin/realms/{realm}/users
                created = true;

                // 2) Re-fetch user id
                var matches = await kc.UsersAll3Async(
                    briefRepresentation: true,
                    email: null,
                    emailVerified: null,
                    enabled: null,
                    exact: true,
                    first: null,
                    firstName: null,
                    idpAlias: null,
                    idpUserId: null,
                    lastName: null,
                    max: 2,
                    q: null,
                    search: null,
                    username: username,
                    realm: realm,
                    cancellationToken: ct);

                userId = matches?.FirstOrDefault()?.Id;
                if (string.IsNullOrWhiteSpace(userId))
                    throw new InvalidOperationException("User created but could not re-fetch its ID.");
            }
            catch (ApiException ex) when (ex.StatusCode == (int)HttpStatusCode.Conflict)
            {
                // User exists → fetch ID
                var matches = await kc.UsersAll3Async(
                    briefRepresentation: true,
                    email: null,
                    emailVerified: null,
                    enabled: null,
                    exact: true,
                    first: null,
                    firstName: null,
                    idpAlias: null,
                    idpUserId: null,
                    lastName: null,
                    max: 2,
                    q: null,
                    search: null,
                    username: username,
                    realm: realm,
                    cancellationToken: ct);

                userId = matches?.FirstOrDefault()?.Id;
            }
            catch (Exception ex)
            {
                results.Add(new(username, null, created, passwordSet, $"Create lookup error: {ex.Message}"));
                continue;
            }

            // 3) Set password = NationalId
            try
            {
                if (!string.IsNullOrWhiteSpace(userId))
                {
                    var cred = new CredentialRepresentation
                    {
                        Type = "password",
                        Value = username, // NationalId as default password
                        Temporary = false
                    };

                    await kc.ResetPasswordAsync(cred, realm, userId, ct);
                    passwordSet = true;
                }

                results.Add(new(username, userId, created, passwordSet, null));
            }
            catch (Exception ex)
            {
                results.Add(new(username, userId, created, passwordSet, $"Password set error: {ex.Message}"));
            }
        }

        return Results.Ok(results);
    }
}

// ✅ Source-generated JSON context for your request/response types
[JsonSerializable(typeof(KeycloakUserBulkEndpoints.Person[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.Person>))]
[JsonSerializable(typeof(KeycloakUserBulkEndpoints.BulkCreateUserResult[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.BulkCreateUserResult>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }
