using System.Text.Json.Serialization;

namespace RefreshTokenAuth.Models;

public class Usuario
{
    public string? Nick { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Senha { get; set; }
    public string? Role { get; set; }
}