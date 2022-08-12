using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using RefreshTokenAuth.Models;
using RefreshTokenAuth.Repositorios;
using RefreshTokenAuth.Servicos;

namespace RefreshTokenAuth.Controllers;

[ApiController]
public class LoginController : ControllerBase
{
    [HttpPost]
    [Route("login")]
    public async Task<ActionResult<dynamic>> Authenticate(Usuario model)
    {
        Usuario? usuario = await UsuarioRepositorio.Buscar(model.Nick, model.Senha);

        if (usuario == null)
        {
            return NotFound(new { mensagem = "Usuário ou senha inválidos" });
        }

        string token = TokenServico.GerarToken(usuario);

        string refreshToken = TokenServico.GerarRefreshToken();

        TokenServico.SalvarRefreshToken(usuario.Nick, refreshToken);

        usuario.Senha = null;

        return new { usuario, token, refreshToken };
    }

    [HttpPost]
    [Route("refresh")]
    public IActionResult Refresh(RefreshTokenRequest request)
    {
        ClaimsPrincipal principal = TokenServico.BuscarDadosDoTokenExpirado(request.Token);

        string? nick = principal.Identity?.Name;

        string refreshTokenSalvo = TokenServico.GetRefreshToken(nick);
        
        if(refreshTokenSalvo != request.RefreshToken)
        {
            return BadRequest("Refresh token inválido");
        }

        string novoToken = TokenServico.GerarToken(principal.Claims);
        string novoRefreshToken = TokenServico.GerarRefreshToken();

        TokenServico.ExcluirRefreshToken(nick, request.RefreshToken);
        TokenServico.SalvarRefreshToken(nick, novoRefreshToken);

        return new ObjectResult(new
        {
            token = novoToken,
            refreshToken = novoRefreshToken
        });

    }
}