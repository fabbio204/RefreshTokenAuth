using RefreshTokenAuth.Models;

namespace RefreshTokenAuth.Repositorios;

public class UsuarioRepositorio
{
    public static Task<Usuario?> Buscar(string nick, string senha)
    {
        List<Usuario> lista = new()
        {
            new Usuario() { Nick = "gerente", Senha = "123", Role = "gerente" },
            new Usuario() { Nick = "Funcionário 1", Senha = "321", Role = "empregado" },
        };

        Usuario? usuario = lista.FirstOrDefault(x => x.Nick.ToLower().Equals(nick) && x.Senha.Equals(senha));
        
        return Task.FromResult(usuario);
    }
}