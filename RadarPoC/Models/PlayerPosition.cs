namespace RadarPoC.Models;

public class PlayerPosition
{
    public int TransientId { get; set; }
    public float X { get; set; }
    public float Y { get; set; }
    public float Z { get; set; }
    public int Port { get; set; }
    public long Timestamp { get; set; }
    public string? Name { get; set; }
    public string? SteamId { get; set; }
}
