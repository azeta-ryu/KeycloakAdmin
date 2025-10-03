#nullable enable

using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using KeycloakAdmin.OpenApi;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
// ReSharper disable CheckNamespace

namespace KeycloakAdmin
{
    // ============================================================
    // Options
    // ============================================================
    public enum KeycloakAuthFlow
    {
        ClientCredentials = 0,
        Password = 1
    }

    public sealed class KeycloakClientOptions
    {
        /// <summary>e.g. "https://keycloak.example.com"</summary>
        public string Host { get; set; } = "";
        /// <summary>Realm that issues the admin token (the realm of the client).</summary>
        public string Realm { get; set; } = "master";
        public string ClientId { get; set; } = "";
        /// <summary>Client secret (required for confidential clients; optional for public clients using password flow).</summary>
        public string ClientSecret { get; set; } = "";
        /// <summary>Optional scopes; leave null/empty for defaults.</summary>
        public string? Scope { get; set; }
        /// <summary>Seconds subtracted from server expiry to refresh early.</summary>
        public int RefreshSkewSeconds { get; set; } = 60;
        /// <summary>Optional override for the token endpoint URL.</summary>
        public string? TokenEndpointOverride { get; set; }

        /// <summary>Which OAuth2/OIDC flow to use to obtain tokens.</summary>
        public KeycloakAuthFlow Flow { get; set; } = KeycloakAuthFlow.ClientCredentials;

        /// <summary>Required when Flow=Password (Direct Access Grants must be enabled for the client).</summary>
        public string? Username { get; set; }
        /// <summary>Required when Flow=Password.</summary>
        public string? Password { get; set; }

        // Startup connectivity probe
        public bool StartupProbeEnabled { get; set; } = true;
        public int StartupProbeTimeoutSeconds { get; set; } = 10;
        /// <summary>If true, failures during probe throw and stop the app; otherwise they log warnings.</summary>
        public bool FailFastOnStartup { get; set; } = true;

        // Logging toggles & limits
        public bool LogRequests { get; set; } = true;
        public bool LogRequestBody { get; set; } = true;
        public bool LogResponseBody { get; set; } = true;
        /// <summary>Maximum bytes of request/response bodies to log (truncated beyond this).</summary>
        public int MaxBodyLogBytes { get; set; } = 4096;
    }

    // ============================================================
    // Service registration (extension)
    // ============================================================
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers KeycloakOpenApiClient as an <see cref="IKeycloakOpenApiClient"/> using a named HttpClient,
        /// attaches bearer tokens, logs requests/responses, and runs a startup connectivity probe.
        /// Expects NSwag to generate with: InjectHttpClient=true, UseBaseUrl=false, JsonLibrary=SystemTextJson.
        /// </summary>
        public static IServiceCollection AddKeycloakHttpClient(
            this IServiceCollection services,
            Action<KeycloakClientOptions> configure)
        {
            services.Configure(configure);
            services.AddMemoryCache();

            services.AddSingleton<IKeycloakTokenProvider, KeycloakTokenProvider>();
            services.AddTransient<LoggingHandler>();
            services.AddTransient<BearerTokenHandler>();
            services.AddHostedService<KeycloakStartupProbe>();

            // Named client so the startup probe can use the same pipeline (and thus be logged)
            services.AddHttpClient("keycloak-admin")
                .ConfigureHttpClient((sp, http) =>
                {
                    var opts = sp.GetRequiredService<IOptions<KeycloakClientOptions>>().Value;
                    http.BaseAddress = new Uri(opts.Host); // UseBaseUrl=false → rely on BaseAddress
                    http.DefaultRequestHeaders.Accept.Add(
                        new MediaTypeWithQualityHeaderValue("application/json"));
                })
                .AddHttpMessageHandler<LoggingHandler>()      // outermost: log everything
                .AddHttpMessageHandler<BearerTokenHandler>(); // then authorization

            // Bind the generated interface to the implementation using the named pipeline
            services.AddTransient<IKeycloakOpenApiClient>(provider =>
            {
                var httpFactory = provider.GetRequiredService<IHttpClientFactory>();
                var http = httpFactory.CreateClient("keycloak-admin");
                // NSwag with InjectHttpClient=true → ctor(HttpClient)
                return new KeycloakOpenApiClient(http);
            });

            return services;
        }
    }

    // ============================================================
    // Token provider (with rich error logging/explanations)
    // ============================================================
    internal interface IKeycloakTokenProvider
    {
        Task<string> GetAccessTokenAsync(CancellationToken ct = default);
    }

    internal sealed class KeycloakTokenProvider : IKeycloakTokenProvider
    {
        private readonly IMemoryCache _cache;
        private readonly IOptions<KeycloakClientOptions> _options;
        private readonly ILogger<KeycloakTokenProvider> _log;

        public KeycloakTokenProvider(
            IMemoryCache cache,
            IOptions<KeycloakClientOptions> options,
            ILogger<KeycloakTokenProvider> log)
        {
            _cache = cache;
            _options = options;
            _log = log;
        }

        public async Task<string> GetAccessTokenAsync(CancellationToken ct = default)
        {
            var o = _options.Value;
            // Include flow/username/scope in the cache key to avoid collisions
            var cacheKey = $"kc_token::{o.Host}::{o.Realm}::{o.ClientId}::{o.Flow}::{o.Username ?? ""}::{o.Scope ?? ""}";

            if (_cache.TryGetValue<string>(cacheKey, out var cached))
                return cached;

            var token = await RequestTokenAsync(o, ct).ConfigureAwait(false);

            var lifetime = TimeSpan.FromSeconds(
                Math.Max(1, token.ExpiresIn - Math.Abs(o.RefreshSkewSeconds)));
            _cache.Set(cacheKey, token.AccessToken, lifetime);

            return token.AccessToken;
        }

        private static string Truncate(string s, int max)
            => string.IsNullOrEmpty(s) ? s : (s.Length <= max ? s : s[..max] + "…(truncated)");

        private static string RedactSecrets(string s) =>
            Regex.Replace(s,
                @"(""(?:client_secret|password|access_token|refresh_token)""\s*:\s*"")(.*?)("")",
                "$1***$3",
                RegexOptions.IgnoreCase);

        private async Task<TokenResponse> RequestTokenAsync(KeycloakClientOptions o, CancellationToken ct)
        {
            var tokenUrl = o.TokenEndpointOverride ?? $"{o.Host.TrimEnd('/')}/realms/{o.Realm}/protocol/openid-connect/token";

            using var http = new HttpClient(new SocketsHttpHandler
            {
                AutomaticDecompression = System.Net.DecompressionMethods.All
            }, disposeHandler: true);

            // Build form pairs based on selected flow
            var pairs = new List<KeyValuePair<string, string>>();

            if (o.Flow == KeycloakAuthFlow.ClientCredentials)
            {
                pairs.Add(new("grant_type", "client_credentials"));
                pairs.Add(new("client_id", o.ClientId));
                pairs.Add(new("client_secret", o.ClientSecret));
                if (!string.IsNullOrWhiteSpace(o.Scope))
                    pairs.Add(new("scope", o.Scope!));
            }
            else // Password flow
            {
                if (string.IsNullOrWhiteSpace(o.Username) || string.IsNullOrWhiteSpace(o.Password))
                    throw new InvalidOperationException("Username and Password must be provided for password grant_type.");

                pairs.Add(new("grant_type", "password"));
                pairs.Add(new("client_id", o.ClientId));
                if (!string.IsNullOrWhiteSpace(o.ClientSecret))
                    pairs.Add(new("client_secret", o.ClientSecret)); // confidential client (optional)
                pairs.Add(new("username", o.Username!));
                pairs.Add(new("password", o.Password!));
                if (!string.IsNullOrWhiteSpace(o.Scope))
                    pairs.Add(new("scope", o.Scope!));
            }

            using var form = new FormUrlEncodedContent(pairs);

            _log.LogInformation(
                "Keycloak token → POST {Url} (flow={Flow}, client_id={ClientId}, realm={Realm})",
                tokenUrl, o.Flow, o.ClientId, o.Realm);

            using var res = await http.PostAsync(tokenUrl, form, ct).ConfigureAwait(false);
            var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!res.IsSuccessStatusCode)
            {
                var (error, description) = TryParseTokenError(body);
                var hint = ErrorExplainer.BuildTokenErrorHelp(
                    (int)res.StatusCode, error, description, o);

                _log.LogError(
                    "Keycloak token request failed ({Status} {Reason}). Error: {Error}. Description: {Description}. Hint: {Hint}. Body: {Body}",
                    (int)res.StatusCode, res.ReasonPhrase, error ?? "(none)", description ?? "(none)",
                    hint, Truncate(RedactSecrets(body), 400));

                throw new InvalidOperationException(
                    $"Token request failed ({(int)res.StatusCode} {res.ReasonPhrase}). " +
                    $"{(string.IsNullOrEmpty(error) ? "" : $"Error='{error}'. ")}" +
                    $"{(string.IsNullOrEmpty(description) ? "" : $"Description='{description}'. ")}" +
                    $"Hint: {hint}");
            }

            _log.LogInformation(
                "Keycloak token ← {Status} POST {Url}",
                (int)res.StatusCode, tokenUrl);

            var dto = JsonSerializer.Deserialize(body, KeycloakJsonContext.Default.TokenResponse)
                      ?? throw new InvalidOperationException("Empty token response.");
            if (string.IsNullOrWhiteSpace(dto.AccessToken))
                throw new InvalidOperationException("Token response missing access_token.");
            return dto;
        }

        private static (string? error, string? description) TryParseTokenError(string body)
        {
            try
            {
                var obj = JsonSerializer.Deserialize(body, KeycloakJsonContext.Default.TokenErrorBody);
                return (obj?.Error, obj?.ErrorDescription);
            }
            catch { return (null, null); }
        }
    }

    // ============================================================
    // Auth handler (adds Bearer token)
    // ============================================================
    internal sealed class BearerTokenHandler : DelegatingHandler
    {
        private readonly IKeycloakTokenProvider _tokens;
        public BearerTokenHandler(IKeycloakTokenProvider tokens) => _tokens = tokens;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var token = await _tokens.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    // ============================================================
    // Logging handler (endpoint + request/response bodies)
    // ============================================================
    internal sealed class LoggingHandler : DelegatingHandler
    {
        private readonly ILogger<LoggingHandler> _log;
        private readonly KeycloakClientOptions _opts;

        public LoggingHandler(ILogger<LoggingHandler> log, IOptions<KeycloakClientOptions> opts)
        {
            _log = log;
            _opts = opts.Value;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!_opts.LogRequests)
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            string url = request.RequestUri?.ToString() ?? "(null)";
            string method = request.Method.Method;

            // Request body (buffer safely; only text-ish content)
            string? reqBody = null;
            if (_opts.LogRequestBody && request.Content is not null && ShouldLogBody(request.Content))
            {
                await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
                reqBody = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                reqBody = Truncate(Redact(reqBody), _opts.MaxBodyLogBytes);
            }

            _log.LogInformation("Keycloak → {Method} {Url}", method, url);
            if (!string.IsNullOrEmpty(reqBody))
                _log.LogInformation("Keycloak RequestBody: {Body}", reqBody);

            var sw = Stopwatch.StartNew();
            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            sw.Stop();

            // Response body
            string? respBody = null;
            if (_opts.LogResponseBody && response.Content is not null && ShouldLogBody(response.Content))
            {
                await response.Content.LoadIntoBufferAsync().ConfigureAwait(false);
                respBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                respBody = Truncate(Redact(respBody), _opts.MaxBodyLogBytes);
            }

            _log.LogInformation("Keycloak ← {Status} {Method} {Url} ({Elapsed} ms)",
                (int)response.StatusCode, method, url, sw.ElapsedMilliseconds);

            if (!string.IsNullOrEmpty(respBody))
                _log.LogInformation("Keycloak ResponseBody: {Body}", respBody);

            return response;
        }

        private static bool ShouldLogBody(HttpContent content)
        {
            var ct = content.Headers.ContentType?.MediaType?.ToLowerInvariant();
            if (string.IsNullOrEmpty(ct)) return false;
            return ct.StartsWith("application/json")
                || ct.StartsWith("text/")
                || ct.Contains("xml");
        }

        private static string Truncate(string s, int max)
            => s.Length <= max ? s : s[..max] + "…(truncated)";

        // Naive redaction for common secret fields (expanded for tokens)
        private static readonly Regex SecretFields = new(
            @"(?<key>""(?:client_secret|clientSecret|password|access_token|refresh_token)""\s*:\s*"")(.*?)(?=""|\s)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static string Redact(string s)
            => SecretFields.Replace(s, m => $"{m.Groups["key"].Value}***");
    }

    // ============================================================
    // Startup connectivity probe (uses named client + relative URL)
    // ============================================================
    internal sealed class KeycloakStartupProbe : IHostedService
    {
        private readonly IServiceProvider _sp;
        private readonly ILogger<KeycloakStartupProbe> _log;
        private readonly IOptions<KeycloakClientOptions> _options;

        public KeycloakStartupProbe(IServiceProvider sp, ILogger<KeycloakStartupProbe> log, IOptions<KeycloakClientOptions> options)
        {
            _sp = sp;
            _log = log;
            _options = options;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            var o = _options.Value;
            if (!o.StartupProbeEnabled)
            {
                _log.LogInformation("Keycloak startup probe disabled.");
                return;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, o.StartupProbeTimeoutSeconds)));

            try
            {
                _log.LogInformation("Keycloak startup probe: acquiring token…");
                var tokens = _sp.GetRequiredService<IKeycloakTokenProvider>();
                var token = await tokens.GetAccessTokenAsync(cts.Token);

                _log.LogInformation("Keycloak startup probe: calling /admin/serverinfo…");
                var factory = _sp.GetRequiredService<IHttpClientFactory>();
                using var http = factory.CreateClient("keycloak-admin"); // uses LoggingHandler + BaseAddress

                using var res = await http.GetAsync("admin/serverinfo", cts.Token).ConfigureAwait(false);
                var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (res.IsSuccessStatusCode)
                {
                    _log.LogInformation("Keycloak startup probe OK: {Status} {Reason}", (int)res.StatusCode, res.ReasonPhrase);
                    return;
                }

                var hint = ErrorExplainer.BuildAdminCallHelp((int)res.StatusCode, body);
                var message = $"Keycloak startup probe failed ({(int)res.StatusCode} {res.ReasonPhrase}). Hint: {hint}. Body: {Truncate(body, 400)}";

                if (o.FailFastOnStartup)
                {
                    _log.LogError("{Message}", message);
                    throw new InvalidOperationException(message);
                }
                else
                {
                    _log.LogWarning("{Message}", message);
                }
            }
            catch (OperationCanceledException oce)
            {
                var msg = $"Keycloak startup probe timed out after {o.StartupProbeTimeoutSeconds}s. " +
                          "Hint: check network/DNS, Keycloak availability, and the Host URL.";
                if (o.FailFastOnStartup) throw new InvalidOperationException(msg, oce);
                _log.LogWarning(oce, "{Message}", msg);
            }
            catch (HttpRequestException hre) when (hre.InnerException is AuthenticationException)
            {
                var msg = "Keycloak startup probe failed due to TLS/SSL error. " +
                          "Hint: verify HTTPS certificate (trust chain, hostname) or use a valid CA-signed cert.";
                if (o.FailFastOnStartup) throw new InvalidOperationException(msg, hre);
                _log.LogWarning(hre, "{Message}", msg);
            }
            catch (HttpRequestException hre) when (hre.InnerException is SocketException se)
            {
                var msg = $"Keycloak startup probe failed to connect (socket error: {se.SocketErrorCode}). " +
                          "Hint: check Host, DNS, firewall, or container networking.";
                if (o.FailFastOnStartup) throw new InvalidOperationException(msg, hre);
                _log.LogWarning(hre, "{Message}", msg);
            }
            catch (Exception ex)
            {
                var msg = "Keycloak startup probe failed. See inner exception and logs for details.";
                if (o.FailFastOnStartup) throw new InvalidOperationException(msg, ex);
                _log.LogWarning(ex, "{Message}", msg);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        private static string Truncate(string? s, int max) =>
            string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max] + "...");
    }

    // ============================================================
    // Error explanation helpers
    // ============================================================
    internal static class ErrorExplainer
    {
        public static string BuildTokenErrorHelp(int status, string? error, string? description, KeycloakClientOptions o)
        {
            // Normalize
            var err = (error ?? "").ToLowerInvariant();
            var desc = (description ?? "").ToLowerInvariant();

            if (status == 401 && (err == "unauthorized_client" || desc.Contains("not enabled to retrieve service account")))
            {
                return
                    "Enable **Client authentication** and **Service accounts roles** on the client; " +
                    "use the realm where the client exists; then use the client's **Credentials → Client secret**.";
            }

            if (status == 401 && (err == "invalid_client" || desc.Contains("invalid client credentials")))
            {
                return
                    "The **client secret** is wrong or rotated. Copy the current secret from " +
                    "Clients → your client → **Credentials**, and ensure the **Realm** matches the client's realm.";
            }

            if (status == 400 && err == "invalid_grant")
            {
                if (o.Flow == KeycloakAuthFlow.ClientCredentials)
                {
                    return
                        "Grant type is invalid for this client. Ensure `grant_type=client_credentials` " +
                        "and that **Service accounts roles** is enabled.";
                }

                // Password grant specifics
                if (desc.Contains("invalid user credentials")) return "Invalid username or password.";
                if (desc.Contains("user disabled") || desc.Contains("account disabled")) return "User account is disabled.";
                if (desc.Contains("user not found")) return "User not found in the realm.";
                if (desc.Contains("direct grant is disabled") || desc.Contains("direct access grants"))
                    return "Enable **Direct Access Grants** for this client (Client → Settings → Enable Direct Access Grants).";

                return
                    "Password grant failed. Check username/password, that the user exists and is enabled, " +
                    "and that the client has **Direct Access Grants** enabled.";
            }

            if (status == 404)
            {
                return
                    "Token URL not found. Check `Host` and `Realm` (the realm in the URL must be the client's realm), " +
                    "and ensure the Keycloak base URL is correct.";
            }

            return
                "Check that the client configuration matches the chosen flow: " +
                "**Client authentication** & **Service accounts roles** for client credentials; " +
                "**Direct Access Grants** for password flow. Also verify the **Realm** and **Client secret** (if confidential).";
        }

        public static string BuildAdminCallHelp(int status, string body)
        {
            var lower = (body ?? "").ToLowerInvariant();

            if (status == 403 || lower.Contains("not authorized") || lower.Contains("forbidden"))
            {
                return
                    "Service account is authenticated but missing roles. In the realm you're calling, " +
                    "grant the service account roles under **Service accounts roles** — e.g., `realm-management` → `view-realm` " +
                    "(or `realm-admin` if needed).";
            }

            if (status == 401)
            {
                return
                    "Bearer token invalid/expired. Ensure token retrieval works and the Authorization header is present.";
            }

            if (status == 404)
            {
                return
                    "Endpoint not found. Verify the Keycloak version and base URL. `/admin/serverinfo` " +
                    "exists in modern versions; ensure you're calling the correct base host.";
            }

            return "Inspect response body for details; verify roles, token scope, and endpoint path.";
        }
    }

    // ============================================================
    // JSON DTOs + Source-generated context (no reflection at runtime)
    // ============================================================
    internal sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken = null,
        [property: JsonPropertyName("refresh_expires_in")] int? RefreshExpiresIn = null
    );

    internal sealed record TokenErrorBody(
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription
    );

    [JsonSourceGenerationOptions(
        GenerationMode = JsonSourceGenerationMode.Metadata, // trim-friendly; no reflection at runtime
        PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never)]
    [JsonSerializable(typeof(TokenResponse))]
    [JsonSerializable(typeof(TokenErrorBody))]
    internal sealed partial class KeycloakJsonContext : JsonSerializerContext;
}
