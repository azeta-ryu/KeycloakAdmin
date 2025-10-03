# Cliente HTTP de Keycloak Admin para .NET

Un envoltorio pragmático y amigable con DI alrededor de un **cliente de la API de Admin de Keycloak generado con NSwag**.  
Aporta:

- Adquisición de tokens OAuth2 (**client credentials** y **password**)
- Inyección de autorización **Bearer** vía `HttpMessageHandler`
- **Registro** estructurado de solicitudes/respuestas con **redacción** y **truncado** seguro
- Una **sonda de conectividad al inicio** (`/admin/serverinfo`) con sugerencias legibles
- **Caché** de tokens con adelanto de renovación configurable
- DTOs con `System.Text.Json` **generados por fuente** (sin reflexión en tiempo de ejecución)

> Funciona con una cuenta de servicio de Keycloak (recomendado) o con credenciales de usuario (Direct Access Grants).

---

## Contenido

- [Inicio rápido](#inicio-rápido)
- [Configuración](#configuración)
- [Uso](#uso)
- [Notas de generación con NSwag](#notas-de-generación-con-nswag)
- [Registro (logging)](#registro-logging)
- [Sonda de inicio](#sonda-de-inicio)
- [Caché de token y actualización](#caché-de-token-y-actualización)
- [Solución de problemas](#solución-de-problemas)
- [Preguntas frecuentes](#preguntas-frecuentes)
- [Licencia](#licencia)

---

## Inicio rápido

### 1) Genera el cliente OpenAPI (NSwag)

Asegúrate de tener un cliente generado que exponga `KeycloakAdmin.OpenApi.IKeycloakOpenApiClient` y un constructor concreto `KeycloakOpenApiClient(HttpClient http)`. Consulta [Notas de generación con NSwag](#notas-de-generación-con-nswag).

### 2) Registra los servicios

En tu aplicación ASP.NET Core (por ejemplo, `.NET 6+`), conecta todo con una sola extensión:

```csharp
using KeycloakAdmin;
using KeycloakAdmin.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// Opción A: enlazar desde configuración (recomendado)
builder.Services.AddKeycloakHttpClient(opts =>
{
    builder.Configuration.GetSection("Keycloak").Bind(opts);
});

// Opción B: configurar en línea
// builder.Services.AddKeycloakHttpClient(opts =>
// {
//     opts.Host = "https://keycloak.example.com";
//     opts.Realm = "master";
//     opts.ClientId = "admin-cli";
//     opts.ClientSecret = "super-secret";
//     opts.Flow = KeycloakAuthFlow.ClientCredentials;
// });

var app = builder.Build();

app.MapGet("/server-info", async (IKeycloakOpenApiClient kc) =>
{
    // Ejemplo: llama a cualquier endpoint admin generado; BaseAddress ya está configurado
    // Sustituye por los nombres reales generados (p. ej., AdminServerinfoAsync())
    return Results.Ok(await kc.AdminServerinfoAsync());
});

app.Run();
```

### 3) Configura `appsettings.json` (ejemplo)

```json
{
  "Keycloak": {
    "Host": "https://keycloak.example.com",
    "Realm": "master",
    "ClientId": "my-admin-client",
    "ClientSecret": "replace-me",
    "Scope": null,
    "RefreshSkewSeconds": 60,
    "TokenEndpointOverride": null,
    "Flow": 0,                         // 0 = ClientCredentials, 1 = Password
    "Username": null,                  // requerido para Password flow
    "Password": null,                  // requerido para Password flow

    "StartupProbeEnabled": true,
    "StartupProbeTimeoutSeconds": 10,
    "FailFastOnStartup": true,

    "LogRequests": true,
    "LogRequestBody": true,
    "LogResponseBody": true,
    "MaxBodyLogBytes": 4096
  }
}
```

---

## Configuración

`KeycloakClientOptions`:

| Opción | Tipo | Predeterminado | Notas |
|---|---|---:|---|
| `Host` | string | `""` | URL base de Keycloak, p. ej. `https://keycloak.example.com`. Se usa como `HttpClient.BaseAddress`. |
| `Realm` | string | `"master"` | Realm para la emisión del token (el **realm del cliente**). |
| `ClientId` | string | `""` | Id del cliente OAuth2. |
| `ClientSecret` | string | `""` | Requerido para clientes **confidenciales**; opcional para clientes públicos usando password flow. |
| `Scope` | string? | `null` | Scopes opcionales (separados por espacios). |
| `RefreshSkewSeconds` | int | `60` | Renueva el token antes restando estos segundos a `expires_in`. |
| `TokenEndpointOverride` | string? | `null` | Sobrescribe la URL del endpoint de token si es necesario. |
| `Flow` | `KeycloakAuthFlow` | `ClientCredentials` | `ClientCredentials` o `Password` (Direct Access Grants). |
| `Username` | string? | `null` | Requerido para el flujo `Password`. |
| `Password` | string? | `null` | Requerido para el flujo `Password`. |
| `StartupProbeEnabled` | bool | `true` | Ejecuta una verificación de token + llamada a `/admin/serverinfo` al iniciar. |
| `StartupProbeTimeoutSeconds` | int | `10` | Tiempo de espera para la sonda. |
| `FailFastOnStartup` | bool | `true` | Lanza excepción al fallar la sonda (detiene la app) vs. registrar advertencia y continuar. |
| `LogRequests` | bool | `true` | Activa/desactiva todo el logging HTTP. |
| `LogRequestBody` | bool | `true` | Registra cuerpos de solicitud (solo JSON/texto/XML). Secretos redactados. |
| `LogResponseBody` | bool | `true` | Registra cuerpos de respuesta (solo JSON/texto/XML). Secretos redactados. |
| `MaxBodyLogBytes` | int | `4096` | Trunca cuerpos grandes después de este tamaño en bytes. |

---

## Uso

Una vez registrado, inyecta la interfaz generada donde la necesites:

```csharp
public sealed class MyController : ControllerBase
{
    private readonly IKeycloakOpenApiClient _kc;

    public MyController(IKeycloakOpenApiClient kc) => _kc = kc;

    [HttpGet("realms/{realm}/users")]
    public async Task<IActionResult> GetUsers(string realm)
    {
        // Usa los nombres de métodos generados en tu cliente; pueden variar según la plantilla NSwag
        var users = await _kc.AdminRealmsRealmUsersGetAsync(realm);
        return Ok(users);
    }
}
```

### Elegir un flujo de autenticación

- **Client Credentials (recomendado)**  
  Configura `ClientId`, `ClientSecret`, establece `Flow = ClientCredentials` y otorga a la **cuenta de servicio** los roles necesarios de `realm-management` (p. ej., `view-realm`, o `realm-admin` si realmente necesitas permisos completos).

- **Password (Direct Access Grants)**  
  Establece `Flow = Password` y proporciona `Username` y `Password`.  
  El cliente debe tener habilitado **Direct Access Grants**. `ClientSecret` es opcional para clientes públicos.

---

## Notas de generación con NSwag

Esta librería espera que tu cliente OpenAPI se genere con:

- `InjectHttpClient = true` (el constructor acepta `HttpClient`)
- `UseBaseUrl = false` (el código de DI establece `HttpClient.BaseAddress` con `Host`)
- `JsonLibrary = SystemTextJson`

Ejemplo de `nswag.json` (extracto):

```json
{
  "codeGenerators": {
    "openApiToCSharpClient": {
      "className": "KeycloakOpenApiClient",
      "namespace": "KeycloakAdmin.OpenApi",
      "injectHttpClient": true,
      "useBaseUrl": false,
      "clientBaseClass": null,
      "generateClientInterfaces": true,
      "generateOptionalParameters": true,
      "jsonLibrary": "SystemTextJson"
    }
  }
}
```

> Asegúrate de que la interfaz generada se llame `IKeycloakOpenApiClient` (o ajusta el registro en consecuencia).

---

## Registro (logging)

- El cliente **nombrado** es `keycloak-admin`.  
- Las solicitudes/respuestas se registran con nivel **Information**:
  - Método + URL + estado + milisegundos transcurridos
  - Cuerpos opcionales (solo JSON/texto/XML), con campos **redactados**:
    - `client_secret`, `clientSecret`, `password`, `access_token`, `refresh_token`
  - Los cuerpos se **truncan** a `MaxBodyLogBytes`.

> En producción, considera desactivar `LogRequestBody` / `LogResponseBody` o ampliar la redacción de secretos según tus políticas.

---

## Sonda de inicio

Al iniciar la app (a menos que se desactive):

1. Obtiene un token (usando el flujo configurado).
2. Llama `GET /admin/serverinfo` usando el mismo pipeline (por lo que queda registrado).
3. Si falla, se muestra una **sugerencia legible**.  
   Si `FailFastOnStartup = true`, la app lanza excepción y se detiene; de lo contrario, registra una advertencia y continúa.

Fallos comunes manejados:
- Problemas TLS/SSL → mensaje accionable sobre certificado/nombre de host
- Errores de socket → sugerencias sobre DNS/firewall/red
- Tiempos de espera → sugiere revisar disponibilidad y URL base
- 401/403/404 → explicaciones de roles/endpoint/host mal configurados

---

## Caché de token y actualización

- Los tokens se cachean en `IMemoryCache` con una clave que incluye:
  `Host`, `Realm`, `ClientId`, `Flow`, `Username` y `Scope`.
- Tiempo de vida de caché = `expires_in - RefreshSkewSeconds` (mínimo 1 segundo).
- Cada solicitud saliente usa el token **Bearer** del proveedor; cuando caduca, se obtiene otro de forma transparente.

---

## Solución de problemas

| Síntoma | Causa probable | Qué revisar |
|---|---|---|
| `401 unauthorized_client` o el cuerpo menciona *“not enabled to retrieve service account”* | Flujo de credenciales de cliente sin cuenta de servicio habilitada | En la configuración del cliente, habilita **Client authentication** y **Service accounts roles**. Usa el **Realm** correcto (el del cliente) y el **Client secret** actual (Clients → tu cliente → **Credentials**). |
| `401 invalid_client` o *“invalid client credentials”* | Secreto incorrecto/rotado | Copia el secreto vigente desde la pestaña **Credentials** del cliente. |
| `400 invalid_grant` (client credentials) | Grant incorrecto | Asegura `grant_type=client_credentials` y que **Service accounts roles** esté habilitado. |
| `400 invalid_grant` (password flow) | Usuario/contraseña o DAG no habilitado | Verifica credenciales, que el usuario exista y esté habilitado. Activa **Direct Access Grants** en el cliente. |
| `404` desde el endpoint de token | `Host`/`Realm` incorrecto o ruta personalizada | Verifica `Host` y `Realm`. Usa `TokenEndpointOverride` si tu despliegue usa una ruta no estándar. |
| `403` al llamar endpoints admin | Autenticado pero sin roles necesarios | Otorga a la cuenta de servicio los roles apropiados de `realm-management` en el **realm de destino** (p. ej., `view-realm`, o `realm-admin` si es necesario). |
| Error TLS/SSL durante la sonda | Certificado/nombre de host no válido o CA no confiable | Verifica la cadena de confianza y los hostnames; usa un certificado firmado por una CA válida. |
| Fallos de socket/DNS | Problemas de red o URL | Revisa DNS, firewall, red de contenedores y la URL de `Host`. |

---

## Preguntas frecuentes

**P: ¿Qué versión de .NET se requiere?**  
R: El código utiliza generación de fuente de `System.Text.Json` y `HttpClientFactory`; se recomienda **.NET 6 o superior**.

**P: ¿Puedo cambiar el nivel/salida del logging?**  
R: Sí—esto usa `ILogger<T>`. Configura salidas/niveles con tu proveedor de logging. Activa/desactiva el registro de cuerpos con las opciones.

**P: ¿Y si mi Keycloak está detrás de un proxy inverso con una ruta de token distinta?**  
R: Usa `TokenEndpointOverride` para apuntar directamente al `/protocol/openid-connect/token` correcto.

**P: ¿Puedo llamar endpoints de múltiples realms?**  
R: El realm que emite el token lo define `Realm`. Aun así, puedes llamar endpoints de otros realms si tu cuenta de servicio tiene permisos cruzados y tus métodos generados apuntan a esas rutas.

**P: ¿Se usa refresh token?**  
R: El proveedor se basa en `expires_in` y renovación anticipada; no rota refresh tokens. Cuando se necesita, vuelve a adquirir el access token.

---

## Licencia

MIT (o la licencia de tu proyecto). Añade un archivo `LICENSE` junto a este README.

---

### Créditos

- Construido sobre `HttpClientFactory`, abstracciones `Microsoft.Extensions.*` y clientes generados con NSwag.
- Los secretos se redactan en los logs; aun así, considera tus políticas de registro en producción.
