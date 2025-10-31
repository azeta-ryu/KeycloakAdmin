using System.Net;
using System.Text.Json.Serialization;
using KeycloakAdmin.OpenApi;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KeycloakAdmin.Endpoints;

internal static class KeycloakUserBulkEndpoints
{
    public static void MapKeycloakAdminEndpoints(this IEndpointRouteBuilder app)
    {
        // === User Endpoints ===
        var usersGroup = app.MapGroup("/keycloak/users")
            .WithTags("Keycloak Admin - Users");

        usersGroup.MapPost("/bulk", BulkCreate)
            .WithSummary("Bulk create or update users and set their password.")
            .Produces<List<BulkCreateUserResult>>()
            .Produces(StatusCodes.Status400BadRequest);

        usersGroup.MapGet("/", GetAllUsers)
            .WithSummary("Get users in the realm with optional filters.")
            .Produces<ICollection<UserRepresentation>>()
            .Produces(StatusCodes.Status500InternalServerError);

        // === Group Endpoints ===
        var groupsGroup = app.MapGroup("/keycloak/groups")
            .WithTags("Keycloak Admin - Groups");

        groupsGroup.MapGet("/", GetAllGroups)
            .WithSummary("Get groups in the realm with optional filters.")
            .Produces<ICollection<GroupRepresentation>>()
            .Produces(StatusCodes.Status500InternalServerError);
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

    private static async Task<IResult> GetAllUsers(
        [FromServices] KeycloakOpenApiClient kc,
        [FromServices] IOptions<KeycloakClientOptions> opts,
        [FromQuery] bool? briefRepresentation,
        [FromQuery] string? email,
        [FromQuery] bool? emailVerified,
        [FromQuery] bool? enabled,
        [FromQuery] bool? exact,
        [FromQuery] int? first,
        [FromQuery] string? firstName,
        [FromQuery] string? idpAlias,
        [FromQuery] string? idpUserId,
        [FromQuery] string? lastName,
        [FromQuery] int? max,
        [FromQuery] string? q,
        [FromQuery] string? search,
        [FromQuery] string? username,
        CancellationToken ct)
    {
        var realm = opts.Value.Realm;
        try
        {
            var users = await kc.UsersAll3Async(
                briefRepresentation: briefRepresentation,
                email: email,
                emailVerified: emailVerified,
                enabled: enabled,
                exact: exact,
                first: first,
                firstName: firstName,
                idpAlias: idpAlias,
                idpUserId: idpUserId,
                lastName: lastName,
                max: max,
                q: q,
                search: search,
                username: username,
                realm: realm,
                cancellationToken: ct);

            return Results.Ok(users);
        }
        catch (ApiException ex)
        {
            return Results.Problem(ex.Response, statusCode: ex.StatusCode, title: "Error fetching users");
        }
        catch (Exception ex)
        {
            return Results.Problem(ex.Message, statusCode: 500, title: "Internal server error");
        }
    }

    /// <summary>
    /// Gets all groups in the realm, supporting pagination and searching.
    /// </summary>
    private static async Task<IResult> GetAllGroups(
        [FromServices] KeycloakOpenApiClient kc,
        [FromServices] IOptions<KeycloakClientOptions> opts,
        [FromQuery] bool? briefRepresentation,
        [FromQuery] bool? exact,
        [FromQuery] int? first,
        [FromQuery] int? max,
        [FromQuery] bool? populateHierarchy,
        [FromQuery] string? q,
        [FromQuery] string? search,
        [FromQuery] bool? subGroupsCount,
        CancellationToken ct)
    {
        var realm = opts.Value.Realm;
        try
        {
            var groups = await kc.GroupsAll2Async(
                briefRepresentation: briefRepresentation,
                exact: exact,
                first: first,
                max: max,
                populateHierarchy: populateHierarchy,
                q: q,
                search: search,
                subGroupsCount: subGroupsCount,
                realm: realm,
                cancellationToken: ct);

            return Results.Ok(groups);
        }
        catch (ApiException ex)
        {
            return Results.Problem(ex.Response, statusCode: ex.StatusCode, title: "Error fetching groups");
        }
        catch (Exception ex)
        {
            return Results.Problem(ex.Message, statusCode: 500, title: "Internal server error");
        }
    }
}
[JsonSerializable(typeof(ICollection<UserRepresentation>))]
[JsonSerializable(typeof(List<UserRepresentation>))]
[JsonSerializable(typeof(ICollection<GroupRepresentation>))]
[JsonSerializable(typeof(List<GroupRepresentation>))]
[JsonSerializable(typeof(KeycloakUserBulkEndpoints.Person[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.Person>))]
[JsonSerializable(typeof(KeycloakUserBulkEndpoints.BulkCreateUserResult[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.BulkCreateUserResult>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }