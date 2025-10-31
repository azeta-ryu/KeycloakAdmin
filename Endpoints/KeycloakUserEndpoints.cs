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
    
    public sealed record Person(
        string NationalId, 
        string Email, 
        string Name, 
        string LastName, 
        string? GroupId
    );

    public sealed record BulkCreateUserResult(
        string Username,
        string? UserId,
        bool Created,
        bool PasswordSet,
        bool GroupAssigned,
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
        var tasks = new List<Task<BulkCreateUserResult>>(people.Length);
        foreach (var p in people)
        {
            tasks.Add(CreateUserAsync(p, kc, realm, ct));
        }
        await Task.WhenAll(tasks);
        var results = tasks.Select(t => t.Result).ToList();

        return Results.Ok(results);
    }
    
    private static async Task<BulkCreateUserResult> CreateUserAsync(
        Person p,
        KeycloakOpenApiClient kc,
        string realm,
        CancellationToken ct)
    {
        var username = p.NationalId?.Trim();
        if (string.IsNullOrWhiteSpace(username))
        {
            return new(username ?? "", null, false, false, false, "NationalId is required");
        }

        string? userId = null;
        var created = false;
        var passwordSet = false;
        var groupAssigned = false;
        string? mainError = null;

        try
        {
            var user = new UserRepresentation
            {
                Username = username,
                Email = p.Email,
                FirstName = p.Name,
                LastName = p.LastName,
                Enabled = true
            };

            await kc.UsersPOSTAsync(user, realm, ct);
            created = true;
            
            var matches = await kc.UsersAll3Async(
                briefRepresentation: true, email: null, emailVerified: null, enabled: null,
                exact: true, first: null, firstName: null, idpAlias: null, idpUserId: null,
                lastName: null, max: 2, q: null, search: null, username: username,
                realm: realm, cancellationToken: ct);

            userId = matches?.FirstOrDefault()?.Id;
            if (string.IsNullOrWhiteSpace(userId))
                throw new InvalidOperationException("User created but could not re-fetch its ID.");
        }
        catch (ApiException ex) when (ex.StatusCode == (int)HttpStatusCode.Conflict)
        {
            try
            {
                var matches = await kc.UsersAll3Async(
                    briefRepresentation: true, email: null, emailVerified: null, enabled: null,
                    exact: true, first: null, firstName: null, idpAlias: null, idpUserId: null,
                    lastName: null, max: 2, q: null, search: null, username: username,
                    realm: realm, cancellationToken: ct);

                userId = matches?.FirstOrDefault()?.Id;
            }
            catch (Exception fetchEx)
            {
                return new(username, null, false, false, false, $"User exists, but fetch failed: {fetchEx.Message}");
            }
        }
        catch (Exception ex)
        {
            return new(username, null, created, passwordSet, false, $"Create lookup error: {ex.Message}");
        }

        try
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                return new(username, null, created, false, false, "User ID could not be determined for password set.");
            }
            
            var cred = new CredentialRepresentation
            {
                Type = "password",
                Value = username,
                Temporary = false
            };

            await kc.ResetPasswordAsync(cred, realm, userId, ct);
            passwordSet = true;
            
            if (!string.IsNullOrWhiteSpace(p.GroupId))
            {
                try
                {
                    await kc.GroupsPUT2Async(p.GroupId, realm, userId, ct);
                    groupAssigned = true;
                }
                catch (Exception groupEx)
                {
                    mainError = $"Group assign error: {groupEx.Message}";
                }
            }

            return new(username, userId, created, passwordSet, groupAssigned, mainError);
        }
        catch (Exception ex)
        {
            return new(username, userId, created, passwordSet, false, $"Password set error: {ex.Message}");
        }
    }
}

[JsonSerializable(typeof(KeycloakUserBulkEndpoints.Person[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.Person>))]
[JsonSerializable(typeof(KeycloakUserBulkEndpoints.BulkCreateUserResult[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.BulkCreateUserResult>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }