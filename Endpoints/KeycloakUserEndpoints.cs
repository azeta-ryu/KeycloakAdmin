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

    /// <summary>
    /// Updated Person record to accept a collection of GroupIds.
    /// </summary>
    public sealed record Person(
        string NationalId,
        string Email,
        string Name,
        string LastName,
        IReadOnlyCollection<string>? GroupIds // Changed from string? GroupId
    );

    /// <summary>
    /// Updated result record to report on multiple group assignments.
    /// </summary>
    public sealed record BulkCreateUserResult(
        string Username,
        string? UserId,
        bool Created,
        bool PasswordSet,
        int GroupsRequested, // New: How many non-empty group IDs were provided
        int GroupsAssigned,  // New: How many groups were successfully assigned
        string? Error);

    private static async Task<IResult> BulkCreate(
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
            // Updated return type
            return new(username ?? "", null, false, false, 0, 0, "NationalId is required");
        }

        string? userId = null;
        var created = false;
        var passwordSet = false;
        // groupAssigned (bool) is removed, will be calculated later

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
                // Updated return type
                return new(username, null, false, false, 0, 0, $"User exists, but fetch failed: {fetchEx.Message}");
            }
        }
        catch (Exception ex)
        {
            // Updated return type
            return new(username, null, created, passwordSet, 0, 0, $"Create lookup error: {ex.Message}");
        }

        try
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                // Updated return type
                return new(username, null, created, false, 0, 0, "User ID could not be determined for password set.");
            }

            var cred = new CredentialRepresentation
            {
                Type = "password",
                Value = username,
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
                        // Use GroupsPUT2Async for "Add user to group"
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
            // Updated return type (password set failed, 0 groups processed)
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
internal partial class AppJsonSerializerContext : JsonSerializerContext { }