using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using KeycloakAdmin.OpenApi;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace KeycloakAdmin;

// ---------- options ----------
public sealed class KeycloakClientOptions
{
    /// <summary>e.g. "https://keycloak.example.com"</summary>
    public string Host { get; set; } = "";
    /// <summary>Realm that issues the admin token (often "master").</summary>
    public string Realm { get; set; } = "master";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    /// <summary>Optional scopes; leave null/empty for defaults.</summary>
    public string? Scope { get; set; }
    /// <summary>Seconds subtracted from server expiry to refresh early.</summary>
    public int RefreshSkewSeconds { get; set; } = 60;
    /// <summary>Override the token endpoint if needed.</summary>
    public string? TokenEndpointOverride { get; set; }
}

// ---------- extension ----------
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers KeycloakOpenApiClient as a typed HttpClient that auto-attaches a bearer token.
    /// Usage:
    /// services.AddKeycloakHttpClient(o => {
    ///     o.Host = "https://keycloak.example.com";
    ///     o.Realm = "master";
    ///     o.ClientId = "admin-cli";
    ///     o.ClientSecret = "****";
    /// });
    /// </summary>
    public static IServiceCollection AddKeycloakHttpClient(
        this IServiceCollection services,
        Action<KeycloakClientOptions> configure)
    {
        services.Configure(configure);
        services.AddMemoryCache();
        services.AddTransient<BearerTokenHandler>();

        // Register the typed client that your code will consume
        services.AddHttpClient<KeycloakOpenApiClient>()
            .AddHttpMessageHandler<BearerTokenHandler>()
            .AddTypedClient((http, sp) =>
            {
                var opts = sp.GetRequiredService<IOptions<KeycloakClientOptions>>().Value;

                // NSwag client expects BaseUrl string (not HttpClient.BaseAddress)
                // We still set some sane defaults on the underlying HttpClient
                http.DefaultRequestHeaders.Accept.Add(
                    new MediaTypeWithQualityHeaderValue("application/json"));

                return new KeycloakOpenApiClient(opts.Host, http);
            });

        return services;
    }

    // ---------- token handler ----------
    private sealed class BearerTokenHandler : DelegatingHandler
    {
        private readonly IMemoryCache _cache;
        private readonly IOptions<KeycloakClientOptions> _options;

        public BearerTokenHandler(IMemoryCache cache, IOptions<KeycloakClientOptions> options)
        {
            _cache = cache;
            _options = options;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var token = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private async Task<string> GetAccessTokenAsync(CancellationToken ct)
        {
            var o = _options.Value;
            var cacheKey = $"kc_token::{o.Host}::{o.Realm}::{o.ClientId}";

            if (_cache.TryGetValue<string>(cacheKey, out var cached))
                return cached;

            var token = await RequestTokenAsync(o, ct).ConfigureAwait(false);

            // Cache using expires_in minus skew
            var lifetime = TimeSpan.FromSeconds(
                Math.Max(1, token.ExpiresIn - Math.Abs(o.RefreshSkewSeconds)));

            _cache.Set(cacheKey, token.AccessToken, lifetime);
            return token.AccessToken;
        }

        private static async Task<TokenResponse> RequestTokenAsync(KeycloakClientOptions o, CancellationToken ct)
        {
            var tokenUrl = o.TokenEndpointOverride ?? $"{o.Host.TrimEnd('/')}/realms/{o.Realm}/protocol/openid-connect/token";

            using var http = new HttpClient(new SocketsHttpHandler
            {
                AutomaticDecompression = System.Net.DecompressionMethods.All
            }, disposeHandler: true);

            using var form = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string,string>("grant_type", "client_credentials"),
                new KeyValuePair<string,string>("client_id", o.ClientId),
                new KeyValuePair<string,string>("client_secret", o.ClientSecret),
                // Only send scope when provided
                new KeyValuePair<string,string>("scope", string.IsNullOrWhiteSpace(o.Scope) ? "" : o.Scope!)
            });

            // If scope is empty, Keycloak ignores it; we can avoid sending an empty field:
            if (string.IsNullOrWhiteSpace(o.Scope))
            {
                var f = new[]
                {
                    new KeyValuePair<string,string>("grant_type", "client_credentials"),
                    new KeyValuePair<string,string>("client_id", o.ClientId),
                    new KeyValuePair<string,string>("client_secret", o.ClientSecret),
                };
                using var formNoScope = new FormUrlEncodedContent(f);
                var resNoScope = await http.PostAsync(tokenUrl, formNoScope, ct).ConfigureAwait(false);
                resNoScope.EnsureSuccessStatusCode();
                var jsonNoScope = await resNoScope.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return Deserialize(jsonNoScope);
            }
            else
            {
                var res = await http.PostAsync(tokenUrl, form, ct).ConfigureAwait(false);
                res.EnsureSuccessStatusCode();
                var json = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return Deserialize(json);
            }

            static TokenResponse Deserialize(string json)
            {
                var dto = JsonSerializer.Deserialize<TokenResponse>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                }) ?? throw new InvalidOperationException("Empty token response.");
                if (string.IsNullOrWhiteSpace(dto.AccessToken))
                    throw new InvalidOperationException("Token response did not include access_token.");
                return dto;
            }
        }

        private sealed record TokenResponse(
            [property: JsonPropertyName("access_token")] string AccessToken,
            [property: JsonPropertyName("expires_in")] int ExpiresIn
        );
    }
}