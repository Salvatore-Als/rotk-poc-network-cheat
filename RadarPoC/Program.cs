using RadarPoC.Hubs;
using RadarPoC.Services;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddSignalR();
builder.Services.AddHostedService<PacketCaptureService>();
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.WithOrigins("http://localhost:3000")
     .AllowAnyHeader()
     .AllowAnyMethod()
     .AllowCredentials()));

var app = builder.Build();

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// SignalR hub
app.MapHub<RadarHub>("/hub/radar");

// Fallback → React SPA
app.MapFallbackToFile("index.html");

app.Run("http://0.0.0.0:5000");
