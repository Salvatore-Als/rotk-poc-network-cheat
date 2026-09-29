using Microsoft.AspNetCore.SignalR;

namespace RadarPoC.Hubs;

// Hub SignalR — point de connexion WebSocket entre le serveur C# et le front React.
// Le serveur pousse les positions via hub.Clients.All.SendAsync("positions", ...).
// Le client React reçoit les positions et met à jour le radar canvas.
public sealed class RadarHub : Hub
{
    public override async Task OnConnectedAsync()
    {
        await Clients.Caller.SendAsync("connected", new { message = "RadarPoC connecté — écoute le trafic ROTK" });
        await base.OnConnectedAsync();
    }
}
