using System.Net;
using System.Text.Json.Serialization;
using KeycloakAdmin.OpenApi;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KeycloakAdmin.Endpoints;

internal static class KeycloakUserBulkEndpoints
{
    public static void MapKeycloakEndpoints(this IEndpointRouteBuilder app)
    {
        // --- User Endpoints ---
        var usersGroup = app.MapGroup("/keycloak/users")
            .WithTags("Keycloak - Users");

        usersGroup.MapPost("/bulk", BulkCreateUsers);

        // --- Group Endpoints ---
        var groupsGroup = app.MapGroup("/keycloak/groups")
            .WithTags("Keycloak - Groups");

        groupsGroup.MapGet("/", GetAllGroups);
    }

    // ========================================================================
    // Groups
    // ========================================================================

    private static async Task<IResult> GetAllGroups(
        [FromServices] IKeycloakOpenApiClient kc,
        [FromServices] IOptions<KeycloakClientOptions> opts,
        CancellationToken ct)
    {
        try
        {
            var realm = opts.Value.Realm;

            var groups = await kc.GroupsAll2Async(
                briefRepresentation: true,
                exact: null,
                first: null,
                max: null,
                populateHierarchy: null,
                q: null,
                search: null,
                subGroupsCount: null,
                realm: realm,
                cancellationToken: ct);

            return Results.Ok(groups);
        }
        catch (ApiException apiEx)
        {
            return Results.Problem(
                detail: apiEx.Response,
                statusCode: apiEx.StatusCode,
                title: "Keycloak API Error");
        }
        catch (Exception ex)
        {
            return Results.Problem(
                detail: ex.Message,
                statusCode: 500,
                title: "An unexpected error occurred.");
        }
    }

    // ========================================================================
    // Users
    // ========================================================================

    /// <summary>
    /// Updated Person record to accept a collection of GroupIds.
    /// </summary>
    public sealed record Person(
        string NationalId,
        string Email,
        string Name,
        string LastName,
        string Password, // --- MODIFIED --- Added password field
        IReadOnlyCollection<string>? GroupIds
    );

    /// <summary>
    /// Updated result record to report on multiple group assignments.
    /// </summary>
    public sealed record BulkCreateUserResult(
        string Username,
        string? UserId,
        bool Created,
        bool PasswordSet,
        int GroupsRequested,
        int GroupsAssigned,
        string? Error);

    private static async Task<IResult> BulkCreateUsers(
        [FromServices] IKeycloakOpenApiClient kc,
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
        IKeycloakOpenApiClient kc,
        string realm,
        CancellationToken ct)
    {
        var username = p.NationalId?.Trim();
        if (string.IsNullOrWhiteSpace(username))
        {
            return new(username ?? "", null, false, false, 0, 0, "NationalId is required");
        }

        // --- MODIFIED --- Added password validation
        if (string.IsNullOrWhiteSpace(p.Password))
        {
            return new(username, null, false, false, 0, 0, "Password is required");
        }

        string? userId = null;
        var created = false;
        var passwordSet = false;

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
                return new(username, null, false, false, 0, 0, $"User exists, but fetch failed: {fetchEx.Message}");
            }
        }
        catch (Exception ex)
        {
            return new(username, null, created, passwordSet, 0, 0, $"Create lookup error: {ex.Message}");
        }

        try
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                return new(username, null, created, false, 0, 0, "User ID could not be determined for password set.");
            }

            var cred = new CredentialRepresentation
            {
                Type = "password",
                Value = p.Password, // --- MODIFIED --- Use the password from the request
                Temporary = false
            };

            await kc.ResetPasswordAsync(cred, realm, userId, ct);
            passwordSet = true;

            // --- New Group Assignment Logic ---
            int groupsRequested = 0;
            int groupsAssigned = 0;
            string? groupErrorSummary = null;

            if (p.GroupIds != null)
            {
                var groupErrors = new List<string>();
                foreach (var groupId in p.GroupIds.Where(gid => !string.IsNullOrWhiteSpace(gid)))
                {
                    groupsRequested++;
                    try
                    {
                        await kc.GroupsPUT2Async(groupId, realm, userId, ct);
                        groupsAssigned++;
                    }
                    catch (Exception groupEx)
                    {
                        var errorMsg = groupEx is ApiException apiEx
                            ? $"Group '{groupId}' (Code {apiEx.StatusCode}): {apiEx.Message}"
                            : $"Group '{groupId}': {groupEx.Message}";
                        groupErrors.Add(errorMsg);
                    }
                }

                if (groupErrors.Count > 0)
                {
                    groupErrorSummary = $"Failed {groupErrors.Count} of {groupsRequested} group assignments: " + string.Join("; ", groupErrors);
                }
            }

            return new(username, userId, created, passwordSet, groupsRequested, groupsAssigned, groupErrorSummary);
        }
        catch (Exception ex)
        {
            return new(username, userId, created, passwordSet, 0, 0, $"Password set error: {ex.Message}");
        }
    }
}

[JsonSerializable(typeof(KeycloakUserBulkEndpoints.Person[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.Person>))]
[JsonSerializable(typeof(KeycloakUserBulkEndpoints.BulkCreateUserResult[]))]
[JsonSerializable(typeof(List<KeycloakUserBulkEndpoints.BulkCreateUserResult>))]
[JsonSerializable(typeof(KeycloakAdmin.OpenApi.UserRepresentation))]
[JsonSerializable(typeof(System.Collections.Generic.ICollection<KeycloakAdmin.OpenApi.UserRepresentation>))]
[JsonSerializable(typeof(KeycloakAdmin.OpenApi.CredentialRepresentation))]
[JsonSerializable(typeof(KeycloakAdmin.OpenApi.GroupRepresentation))]
[JsonSerializable(typeof(System.Collections.Generic.ICollection<KeycloakAdmin.OpenApi.GroupRepresentation>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }