using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using RefreshTokenAuth.Models;

namespace RefreshTokenAuth.Servicos;

public class TokenServico
{
    public static string GerarToken(Usuario usuario)
    {
        byte[] chaveSecreta = Encoding.ASCII.GetBytes(Settings.Token);

        // Configura um token para 15 minutos
        SecurityTokenDescriptor tokenDescriptor = new()
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, usuario.Nick),
                new Claim(ClaimTypes.Role, usuario.Role),
            }),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(chaveSecreta),
                SecurityAlgorithms.HmacSha256Signature)
        };

        JwtSecurityTokenHandler tokenHandler = new();

        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }

    public static string GerarToken(IEnumerable<Claim> claims)
    {
        byte[] chaveSecreta = Encoding.ASCII.GetBytes(Settings.Token);

        // Configura um token para 15 minutos
        SecurityTokenDescriptor tokenDescriptor = new()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(chaveSecreta),
                SecurityAlgorithms.HmacSha256Signature)
        };

        JwtSecurityTokenHandler tokenHandler = new();

        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }

    public static string GerarRefreshToken()
    {
        using RandomNumberGenerator gerador = RandomNumberGenerator.Create();

        byte[] numeroAleatorio = new byte[32];

        gerador.GetBytes(numeroAleatorio);

        return Convert.ToBase64String(numeroAleatorio);
    }

    public static ClaimsPrincipal BuscarDadosDoTokenExpirado(string token)
    {
        byte[] chaveSecreta = Encoding.ASCII.GetBytes(Settings.Token);

        TokenValidationParameters parametrosValidacao = new()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(chaveSecreta),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false // não valida se foi expirado
        };

        JwtSecurityTokenHandler tokenHandler = new();

        ClaimsPrincipal? principal =
            tokenHandler.ValidateToken(token, parametrosValidacao, out SecurityToken? securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Token inválido");
        }

        return principal;
    }

    
    // Operações com refresh token
    public static List<(string, string)> RefreshTokens = new();

    public static void SalvarRefreshToken(string usuario, string refreshToken)
    {
        RefreshTokens.Add(new ValueTuple<string, string>(usuario, refreshToken));
    }

    public static string GetRefreshToken(string usuario)
    {
        return RefreshTokens.FirstOrDefault(x=>x.Item1 == usuario).Item2;
    }

    public static void ExcluirRefreshToken(string usuario, string refreshToken)
    {
        (string, string) item = RefreshTokens.FirstOrDefault(x => x.Item1 == usuario && x.Item2 == refreshToken);
        RefreshTokens.Remove(item);
    }
}