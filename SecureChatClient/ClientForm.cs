using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecureChatClient;

public class ClientForm : Form
{
    private readonly TextBox txtMessage;
    private readonly TextBox txtResponse;
    private readonly Button btnSend;
    private readonly X509Certificate2 serverCertificate;

    public ClientForm()
    {
        // Inicializar controles
        txtMessage = new TextBox { Left = 10, Top = 10, Width = 260 };
        txtResponse = new TextBox
        {
            Left = 10,
            Top = 70,
            Width = 350,
            Height = 100,
            Multiline = true,
            ReadOnly = true
        };
        btnSend = new Button { Left = 280, Top = 10, Text = "Enviar", Width = 80 };

        // Configurar el formulario
        Controls.AddRange(new Control[] { txtMessage, btnSend, txtResponse });
        Text = "Cliente Chat Seguro Pro";
        ClientSize = new System.Drawing.Size(380, 190);

        // Cargar certificado del servidor
        serverCertificate = new X509Certificate2("server_public.cer");

        // Suscribir al evento Click
        btnSend.Click += BtnSend_Click;
    }

    private async void BtnSend_Click(object sender, EventArgs e)
    {
        if (string.IsNullOrWhiteSpace(txtMessage.Text))
        {
            MessageBox.Show("Por favor, ingrese un mensaje.", "Aviso",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        btnSend.Enabled = false;
        try
        {
            await SendMessageAsync(txtMessage.Text);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error al enviar mensaje: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            btnSend.Enabled = true;
        }
    }

    private async Task SendMessageAsync(string message)
    {
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", 5000);
        using var stream = client.GetStream();
        using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };
        using var reader = new StreamReader(stream, Encoding.UTF8);

        // Generar clave de sesión y IV
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        // Obtener la clave pública RSA del certificado del servidor
        using var rsaPublicKey = serverCertificate.GetRSAPublicKey()
            ?? throw new InvalidOperationException("No se pudo obtener la clave pública del servidor");

        // Cifrar la clave de sesión y el IV con RSA
        byte[] encryptedKey = rsaPublicKey.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] encryptedIV = rsaPublicKey.Encrypt(aes.IV, RSAEncryptionPadding.OaepSHA256);

        // Enviar clave y IV cifrados
        await writer.WriteLineAsync(Convert.ToBase64String(encryptedKey));
        await writer.WriteLineAsync(Convert.ToBase64String(encryptedIV));

        // Cifrar y enviar el mensaje
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        using var encryptor = aes.CreateEncryptor();
        byte[] encryptedMessage = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);
        await writer.WriteLineAsync(Convert.ToBase64String(encryptedMessage));

        // Recibir y descifrar la respuesta
        string? response = await reader.ReadLineAsync();
        if (response != null)
        {
            byte[] encryptedResponse = Convert.FromBase64String(response);
            using var decryptor = aes.CreateDecryptor();
            byte[] decryptedResponse = decryptor.TransformFinalBlock(encryptedResponse, 0, encryptedResponse.Length);
            string responseText = Encoding.UTF8.GetString(decryptedResponse);

            txtResponse.Text = responseText;
            txtMessage.Clear();
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        serverCertificate.Dispose();
        base.OnFormClosing(e);
    }
}
