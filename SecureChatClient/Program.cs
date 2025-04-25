using Microsoft.Extensions.Configuration;
using System.Windows.Forms;

namespace SecureChatClient;

static class Program
{
    public static IConfiguration Configuration { get; private set; } = null!;

    [STAThread]
    static void Main()
    {
        InitializeConfiguration();
        ApplicationConfiguration.Initialize();
        Application.Run(new ClientForm());
    }

    private static void InitializeConfiguration()
    {
        Configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();
    }
}
