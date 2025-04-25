using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace SecureChatServer;

class Program
{
    private static X509Certificate2? serverCertificate;
    private static readonly CancellationTokenSource cancellationTokenSource = new();
    private static IConfiguration? configuration;

    static async Task Main()
    {
        try
        {
            InitializeConfiguration();
            InitializeCertificate();

            var port = configuration?.GetValue<int>("ServerSettings:Port") ?? 5000;
            using TcpListener listener = new(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"Servidor escuchando en el puerto {port}...");

            while (!cancellationTokenSource.Token.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                _ = HandleClientAsync(client, cancellationTokenSource.Token);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error crítico del servidor: {ex.Message}");
        }
        finally
        {
            serverCertificate?.Dispose();
        }
    }

    private static void InitializeConfiguration()
    {
        configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();
    }

    private static void InitializeCertificate()
    {
        var certPath = configuration?["ServerSettings:CertificatePath"] ?? "server.pfx";
        serverCertificate = new X509Certificate2(certPath);
    }

    private static async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

            // Recibir clave y IV del cliente
            var encryptedKey = Convert.FromBase64String(await reader.ReadLineAsync() ?? string.Empty);
            var encryptedIV = Convert.FromBase64String(await reader.ReadLineAsync() ?? string.Empty);

            // Descifrar la clave y el IV
            byte[] sessionKey, sessionIV;
            using (var rsa = serverCertificate?.GetRSAPrivateKey())
            {
                if (rsa == null) throw new InvalidOperationException("No se pudo obtener la clave privada RSA");
                sessionKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
                sessionIV = rsa.Decrypt(encryptedIV, RSAEncryptionPadding.OaepSHA256);
            }

            // Recibir mensaje cifrado
            string? base64 = await reader.ReadLineAsync();
            if (string.IsNullOrEmpty(base64)) throw new InvalidOperationException("Mensaje vacío recibido");

            byte[] encrypted = Convert.FromBase64String(base64);

            // Descifrar mensaje
            using var aes = Aes.Create();
            aes.Key = sessionKey;
            aes.IV = sessionIV;

            var decryptor = aes.CreateDecryptor();
            byte[] decryptedBytes = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            string message = Encoding.UTF8.GetString(decryptedBytes);

            // Registrar mensaje
            var messageId = Guid.NewGuid();
            Console.WriteLine($"Mensaje {messageId} recibido a las {DateTime.UtcNow:u}");

            // Enviar respuesta cifrada
            string reply = $"Mensaje {messageId} recibido correctamente";
            byte[] replyBytes = Encoding.UTF8.GetBytes(reply);
            var encryptor = aes.CreateEncryptor();
            byte[] replyEncrypted = encryptor.TransformFinalBlock(replyBytes, 0, replyBytes.Length);
            await writer.WriteLineAsync(Convert.ToBase64String(replyEncrypted));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error al procesar cliente: {ex.Message}");
        }
        finally
        {
            client.Close();
        }
    }
}
