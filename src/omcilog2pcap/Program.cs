using System.Globalization;
using System.Text.RegularExpressions;

const string EthType = "88B5";
const string sagecomm_magic = ":omci capture:";
const string lantiq_magic = "[omcid]";

again:
if (args.Length != 1)
{
    Console.WriteLine("drag&drop the omci log to the executable or in this console window");
    var str = Console.ReadLine();
    if (!string.IsNullOrEmpty(str))
    {
        args = new[] { str.Replace("\"", "") };
        goto again;
    }
    return;
}

if (!File.Exists(args[0]))
{
    Console.WriteLine("the log file doesn't exist");
    Console.ReadKey();
    return;
}

await using MemoryStream ms = new();
await ms.WriteAsync(new byte[]
{
    0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
}); // magic header almost constant

var txt = File.ReadAllText(args[0]);

if (txt.Contains(lantiq_magic)) // lantiq
{
    var split = txt.Replace("\r\n", "\n").Replace('\r', '\n').Split(lantiq_magic, StringSplitOptions.RemoveEmptyEntries);
    var lst = split.Where(x => x.Contains("MSG ")).ToList();

    DateTimeOffset? currentDate = null;
    var resetCount = 0;

    for (int i = 0; i < lst.Count; i++)
    {
        var splitlines = lst[i].Split('\n', 2, StringSplitOptions.RemoveEmptyEntries);

        if (!(splitlines.Length > 1))
            continue;

        var mac_olt = "088701701701";
        var mac_ont = "088788000000";

        if (!splitlines[0].Contains("TX"))
        {
            mac_olt = "088788000000";
            mac_ont = "088701701701";
        }

        var hexString = splitlines[1].Trim().Replace(" ", "").Replace("\n", "").Replace("\r", "");
        var time = DateTimeOffset.ParseExact("01/01/2000 " + splitlines[0].Trim().Split(' ').First(),
            "dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture);

        if (currentDate != time)
            resetCount = 0;
        currentDate = time;

        await WriteFrameAsync(time, hexString, i, mac_olt, mac_ont);

        resetCount++;
    }
}
else if (txt.Contains(sagecomm_magic)) // Sagecomm by TIM (at least)
{
    var split = txt.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n', StringSplitOptions.RemoveEmptyEntries);
    var dataLines = split.Where(x => x.Contains(sagecomm_magic)).ToList();

    for (int i = 0; i < dataLines.Count; i++)
    {
        var components = dataLines[i].Split(":");
        var ts = components[0];
        var hexString = components[2];
        var asDouble = double.Parse(ts, CultureInfo.InvariantCulture);
        var time = DateTime.FromFileTimeUtc((long)asDouble * 1000);
        var mac_std = "088788000000";
        await WriteFrameAsync(time, hexString, i, mac_std, mac_std);
    }
}
else if (txt.Contains(" debug: ")) // Cortina Access magic
{
    var blockRegex = new Regex("[\\d]{20} debug: [=]+");
    var lineRegex = new Regex("(?<ts>[\\d]{20})( debug: )([\\d]{8}): (?<data>.+)");
    var goodStrings = blockRegex.Split(txt).Select(x => x.Trim()).ToList();
    goodStrings.Sort();
    for (var i = 0; i < goodStrings.Count; i++)
    {
        var goodString = goodStrings[i];
        var split = goodString.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var hexString = "";
        var ts = "";
        for (var i1 = 0; i1 < split.Length; i1++)
        {
            var underAnalysis = split[i1].Trim();
            var p = lineRegex.Match(underAnalysis);
            if(p.Success)
            {
                ts = p.Groups["ts"].Value;
                var data = p.Groups["data"].Value;
                hexString += data;
            }
        }

        hexString = hexString.Replace(" ", "").Replace("\t", "");
        if(hexString.Length > 0) {
            Console.WriteLine(hexString);
            Console.WriteLine(ts);
            var time = DateTimeOffset.ParseExact("01/01/2000 " + "00:00:00", "dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture);
            var mac_std = "088788000000";
            await WriteFrameAsync(time, hexString, i, mac_std, mac_std);
        }

    }
}
else if (txt.Contains(' ')) // basically others? I've tested it with realtek-based chip logs (afm0002tim)
{
    var split = txt.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n', StringSplitOptions.RemoveEmptyEntries);

    for (int i = 0; i < split.Length; i++)
    {
        var hexString = split[i].Replace(" ", "");
        var time = DateTimeOffset.ParseExact("01/01/2000 " + "00:00:00", "dd/MM/yyyy HH:mm:ss",
            CultureInfo.InvariantCulture);
        var mac_std = "088788000000";
        await WriteFrameAsync(time, hexString, i, mac_std, mac_std);
    }
}
else
{
    Console.WriteLine("unknown format");
    return;
}

await SaveToDisk(ms,
    Path.Combine(Directory.GetCurrentDirectory(), Path.GetFileNameWithoutExtension(args[0]) + ".pcap"));

// -------- Methods

async Task WriteFrameAsync(DateTimeOffset time, string hexString, int nanoSecondsTimestamp, string macSenderHex,
    string macReceiverHex)
{
    var fakeethernetframe = macSenderHex + macReceiverHex + EthType;
    var byteArrayHex = Convert.FromHexString(fakeethernetframe + hexString);
    var byteArrayLength = BitConverter.GetBytes(byteArrayHex.Length);

    await ms.WriteAsync(BitConverter.GetBytes((int)time.ToUnixTimeSeconds())); // EPOCH TIME
    await ms.WriteAsync(BitConverter.GetBytes(nanoSecondsTimestamp)); // TIME IN Nani!?!?!?Seconds
    await ms.WriteAsync(byteArrayLength); // FRAME LENGTH
    await ms.WriteAsync(byteArrayLength); // CAPTURE LENGTH (= FRAME LENGTH)
    await ms.WriteAsync(byteArrayHex); // FRAME CONTENT
}

async Task SaveToDisk(MemoryStream ms, string filePath)
{
    await using FileStream fs = new(filePath, FileMode.Create, FileAccess.Write);
    ms.Position = 0;
    await ms.CopyToAsync(fs);
}