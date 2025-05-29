using System.Net;
using System.Net.NetworkInformation;
using Npgsql;

// Конфигурация БД
const string connectionString = "Host=localhost;Database=netscan;Username=postgres;Password=098068";

// Сканирование всех активных сетей
await ScanAllNetworks();

async Task ScanAllNetworks()
{
    while (true)
    {
        var networks = await GetActiveScanNetworks();

        foreach (var network in networks)
        {
            Console.WriteLine($"Scanning network: {network.Cidr}");
            await ScanNetwork(network.Cidr, network.Id);
            await UpdateLastScanTime(network.Id);
        }

        // Ожидание перед следующим сканированием
        await Task.Delay(TimeSpan.FromMinutes(1));
    }
}

async Task<List<ScanNetwork>> GetActiveScanNetworks()
{
    var networks = new List<ScanNetwork>();

    await using var connection = new NpgsqlConnection(connectionString);
    await connection.OpenAsync();

    await using var cmd = new NpgsqlCommand(
        "SELECT id, network_cidr FROM scan_networks WHERE is_active = TRUE",
        connection);

    await using var reader = await cmd.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        networks.Add(new ScanNetwork(
            reader.GetInt32(0),
            reader.GetString(1)));
    }

    return networks;
}

async Task ScanNetwork(string cidr, int networkId)
{
    var (baseIp, maskLength) = ParseCidr(cidr);
    if (baseIp == null) return;

    uint ip = IpToInt(baseIp);
    uint mask = ~(0xFFFFFFFFu >> maskLength);
    uint firstIp = ip & mask;
    uint lastIp = ip | ~mask;

    // Пропускаем сетевой адрес и широковещательный
    firstIp += 1;
    lastIp -= 1;

    var tasks = new List<Task>();
    var semaphore = new SemaphoreSlim(20); // Ограничиваем количество параллельных задач

    for (uint currentIp = firstIp; currentIp <= lastIp; currentIp++)
    {
        await semaphore.WaitAsync();
        var ipAddress = IntToIp(currentIp);

        tasks.Add(Task.Run(async () =>
        {
            try
            {
                await CheckAndSaveDevice(ipAddress, networkId);
            }
            finally
            {
                semaphore.Release();
            }
        }));
    }

    await Task.WhenAll(tasks);
}

async Task CheckAndSaveDevice(IPAddress ipAddress, int networkId)
{
    try
    {
        using var ping = new Ping();
        var reply = await ping.SendPingAsync(ipAddress, 1000);

        if (reply.Status == IPStatus.Success)
        {
            var macAddress = await GetMacAddress(ipAddress);
            var vendor = macAddress != null ? GetVendorFromMac(macAddress) : null;

            await SaveOrUpdateDevice(ipAddress, macAddress, vendor, networkId);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error checking {ipAddress}: {ex.Message}");
    }
}

async Task<string?> GetMacAddress(IPAddress ipAddress)
{
    try
    {
        var arp = new System.Diagnostics.Process();
        arp.StartInfo.FileName = "arp";
        arp.StartInfo.Arguments = $"-a {ipAddress}";
        arp.StartInfo.UseShellExecute = false;
        arp.StartInfo.RedirectStandardOutput = true;
        arp.StartInfo.CreateNoWindow = true;
        arp.Start();

        var output = await arp.StandardOutput.ReadToEndAsync();
        await arp.WaitForExitAsync();

        var match = System.Text.RegularExpressions.Regex.Match(
            output, @"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");

        if (match.Success)
        {
            // Приводим MAC к стандартному формату с двоеточиями
            return match.Value
                .Replace('-', ':')
                .ToLower();
        }
        return null;
    }
    catch
    {
        return null;
    }
}

string? GetVendorFromMac(string macAddress)
{
    // Здесь можно реализовать поиск производителя по OUI
    // Для простоты возвращаем null
    return null;
}

async Task SaveOrUpdateDevice(
    IPAddress ipAddress,
    string? macAddress,
    string? vendor,
    int networkId)
{
    await using var connection = new NpgsqlConnection(connectionString);
    await connection.OpenAsync();

    await using var cmd = new NpgsqlCommand(
        @"INSERT INTO network_devices (ip_address, mac_address, vendor, last_seen, network_id)
          VALUES (CAST(@ip AS inet), CAST(@mac AS macaddr), @vendor, NOW(), @networkId)
          ON CONFLICT (ip_address, network_id) 
          DO UPDATE SET mac_address = EXCLUDED.mac_address, 
                        vendor = EXCLUDED.vendor,
                        last_seen = EXCLUDED.last_seen",
        connection);

    cmd.Parameters.AddWithValue("ip", ipAddress.ToString());

    // Правильно форматируем MAC-адрес для PostgreSQL
    if (!string.IsNullOrEmpty(macAddress))
    {
        // Преобразуем в формат XX:XX:XX:XX:XX:XX
        var formattedMac = macAddress.Replace('-', ':').ToLower();
        cmd.Parameters.AddWithValue("mac", formattedMac);
    }
    else
    {
        cmd.Parameters.AddWithValue("mac", DBNull.Value);
    }

    cmd.Parameters.AddWithValue("vendor", vendor ?? (object)DBNull.Value);
    cmd.Parameters.AddWithValue("networkId", networkId);

    await cmd.ExecuteNonQueryAsync();
}

async Task UpdateLastScanTime(int networkId)
{
    await using var connection = new NpgsqlConnection(connectionString);
    await connection.OpenAsync();

    await using var cmd = new NpgsqlCommand(
        "UPDATE scan_networks SET last_scan = NOW() WHERE id = @id",
        connection);

    cmd.Parameters.AddWithValue("id", networkId);
    await cmd.ExecuteNonQueryAsync();
}

(IPAddress? baseIp, int maskLength) ParseCidr(string cidr)
{
    var parts = cidr.Split('/');
    if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) ||
        !int.TryParse(parts[1], out var mask) || mask < 0 || mask > 32)
    {
        Console.WriteLine($"Invalid CIDR notation: {cidr}");
        return (null, 0);
    }

    return (ip, mask);
}

uint IpToInt(IPAddress ipAddress)
{
    var bytes = ipAddress.GetAddressBytes();
    if (bytes.Length == 16 && ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
    {
        throw new ArgumentException("IPv6 is not supported");
    }

    if (BitConverter.IsLittleEndian)
    {
        Array.Reverse(bytes);
    }
    return BitConverter.ToUInt32(bytes, 0);
}

IPAddress IntToIp(uint ipAddress)
{
    var bytes = BitConverter.GetBytes(ipAddress);
    if (BitConverter.IsLittleEndian)
    {
        Array.Reverse(bytes);
    }
    return new IPAddress(bytes);
}

record ScanNetwork(int Id, string Cidr);