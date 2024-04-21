using System.Globalization;
using System.Text.RegularExpressions;

const string ethType = "88B5";
const string sagecommMagic = ":omci capture:";
const string lantiqMagic = "[omcid]";
const string huaweiMagic = "OLT->ONT: Priority";
const string macOlt = "088701701701";
const string macOnt = "088788000000";

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

await using MemoryStream outputStream = new();
await outputStream.WriteAsync(new byte[]
{
    0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
}); // magic header almost constant

var txt = File.ReadAllText(args[0]);

if (txt.Contains(lantiqMagic)) // lantiq
{
    var split = txt.Replace("\r\n", "\n").Replace('\r', '\n')
        .Split(lantiqMagic, StringSplitOptions.RemoveEmptyEntries);
    var lst = split.Where(x => x.Contains("MSG ")).ToList();

    for (int i = 0; i < lst.Count; i++)
    {
        var splitLines = lst[i].Split('\n', 2, StringSplitOptions.RemoveEmptyEntries);

        if (!(splitLines.Length > 1))
            continue;

        var isOltToOnt = splitLines[0].Contains("TX");

        var hexString = splitLines[1].Trim().Replace(" ", "").Replace("\n", "").Replace("\r", "");
        var time = DateTimeOffset.ParseExact("01/01/2000 " + splitLines[0].Trim().Split(' ').First(),
            "dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture);

        await WriteFrameAsync(time, hexString, i, isOltToOnt ? macOlt : macOnt, isOltToOnt ? macOnt : macOlt, outputStream);
    }
}
else if (txt.Contains(sagecommMagic)) // Sagecomm by TIM (at least)
{
    var split = txt.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n', StringSplitOptions.RemoveEmptyEntries);
    var dataLines = split.Where(x => x.Contains(sagecommMagic)).ToList();

    for (int i = 0; i < dataLines.Count; i++)
    {
        var components = dataLines[i].Split(":");
        var ts = components[0];
        var hexString = components[2];
        var asDouble = double.Parse(ts, CultureInfo.InvariantCulture);
        var time = DateTime.FromFileTimeUtc((long)asDouble * 1000);
        await WriteFrameAsync(time, hexString, i, macOnt, macOlt, outputStream);
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
        var split = goodString.Replace("\r\n", "\n").Replace('\r', '\n')
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var hexString = "";
        var ts = "";
        foreach (var line in split)
        {
            var underAnalysis = line.Trim();
            var p = lineRegex.Match(underAnalysis);
            if (p.Success)
            {
                ts = p.Groups["ts"].Value;
                var data = p.Groups["data"].Value;
                hexString += data;
            }
        }

        hexString = hexString.Replace(" ", "").Replace("\t", "");
        if (hexString.Length > 0)
        {
            Console.WriteLine(hexString);
            Console.WriteLine(ts);
            var time = DateTimeOffset.ParseExact("01/01/2000 " + "00:00:00", "dd/MM/yyyy HH:mm:ss",
                CultureInfo.InvariantCulture);
            await WriteFrameAsync(time, hexString, i, macOnt, macOlt, outputStream);
        }
    }
}
else if (txt.Contains(huaweiMagic)) // Huawei S800e and B450
{
    var split = txt.Replace("\r\n", "\n").Replace('\r', '\n');
    var blocks = split.Split("\n\n", StringSplitOptions.RemoveEmptyEntries);
    var separatorRegex = new Regex("----+");
    var directionRegex =
        new Regex(
            "^\\[(?<ts>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{6})](?<direction>(OLT|ONT)->(OLT|ONT))");
    foreach (var block in blocks)
    {
        var blockSections = separatorRegex.Split(block);
        if (blockSections.Length == 2)
        {
            var head = blockSections[0].Split("\n")[0];
            var headMatcher = directionRegex.Match(head);
            if (headMatcher.Success)
            {
                var direction = headMatcher.Groups["direction"].Value;
                var isOltToOnt = "OLT->ONT".Equals(direction);
                var ts = headMatcher.Groups["ts"].Value;
                var time = DateTime.ParseExact(ts, "yyyy-MM-dd HH:mm:ss.FFFFFF", CultureInfo.InvariantCulture);
                var data = blockSections[1].Replace(" ", "").Replace("\n", "");
                await WriteFrameAsync(
                    time, data, time.Millisecond * 1000 + time.Microsecond, isOltToOnt ? macOlt : macOnt,
                    isOltToOnt ? macOnt : macOlt, outputStream
                );
            }
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
        await WriteFrameAsync(time, hexString, i, macOlt, macOnt, outputStream);
    }
}
else
{
    Console.WriteLine("unknown format");
    return;
}

var outputFile = Path.Combine(Directory.GetCurrentDirectory(), Path.GetFileNameWithoutExtension(args[0]) + ".pcap");
await SaveToDisk(outputStream,
    outputFile);

Console.WriteLine("File written to " + outputFile);

// -------- Methods

async Task WriteFrameAsync(DateTimeOffset time, string hexString, int microSecondsTimestamp, string macSenderHex,
    string macReceiverHex, MemoryStream stream)
{
    var fakeEthernetFrame = macSenderHex + macReceiverHex + ethType;
    var byteArrayHex = Convert.FromHexString(fakeEthernetFrame + hexString);
    var byteArrayLength = BitConverter.GetBytes(byteArrayHex.Length);

    await stream.WriteAsync(BitConverter.GetBytes((int)time.ToUnixTimeSeconds())); // EPOCH TIME
    await stream.WriteAsync(BitConverter.GetBytes(microSecondsTimestamp)); // TIME IN Nani!?!?!?Seconds
    await stream.WriteAsync(byteArrayLength); // FRAME LENGTH
    await stream.WriteAsync(byteArrayLength); // CAPTURE LENGTH (= FRAME LENGTH)
    await stream.WriteAsync(byteArrayHex); // FRAME CONTENT
}

async Task SaveToDisk(MemoryStream stream, string filePath)
{
    await using FileStream fs = new(filePath, FileMode.Create, FileAccess.Write);
    stream.Position = 0;
    await stream.CopyToAsync(fs);
}