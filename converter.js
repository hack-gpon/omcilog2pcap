const EthType = '88B5';
const sagecomm_magic = ':omci capture:';
const lantiq_magic = '[omcid]';

async function converter(txt) {
  const ms = new MemoryStream();

  // write pcap magic header
  ms.write(Buffer.from([
    0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
  ]));

  if (txt.includes(lantiq_magic)) {
    const split = txt.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split(lantiq_magic).filter((x) => x);
    const lst = split.filter((x) => x.includes('MSG '));

    let currentDate = null;
    let resetCount = 0;

    for (let i = 0; i < lst.length; i++) {
      const splitlines = lst[i].split('\n').filter((x) => x);

      if (splitlines.length <= 1) continue;

      let mac_olt = '088701701701';
      let mac_ont = '088788000000';

      if (!splitlines[0].includes('TX')) {
        mac_olt = '088788000000';
        mac_ont = '088701701701';
      }

      const hexString = splitlines[1].trim().replace(/ /g, '').replace(/\n|\r/g, '');
      const timeStr = '01/01/2000 ' + splitlines[0].trim().split(' ')[0];
      const time = new Date(timeStr);
      if (currentDate !== time) resetCount = 0;
      currentDate = time;

      await writeFrameAsync(time, hexString, i, mac_olt, mac_ont);

      resetCount++;
    }
  } else if (txt.includes(sagecomm_magic)) {
    const split = txt.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').filter((x) => x.includes(sagecomm_magic));
    for (let i = 0; i < split.length; i++) {
      const components = split[i].split(':');
      const ts = components[0];
      const hexString = components[2];
      const asDouble = parseFloat(ts);
      const time = new Date(asDouble * 1000);
      const mac_std = '088788000000';
      await writeFrameAsync(time, hexString, i, mac_std, mac_std);
    }
  } else if (txt.includes(' ')) {
    const split = txt.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    for (let i = 0; i < split.length; i++) {
      const hexString = split[i].replace(/ /g, '');
      const timeStr = '01/01/2000 00:00:00';
      const time = new Date(timeStr);
      const mac_std = '088788000000';
      await writeFrameAsync(time, hexString, i, mac_std, mac_std);
    }
  } else {
    console.log('unknown format');
    return null;
  }

  return ms;
}

async function writeFrameAsync(time, hexString, nanoSecondsTimestamp, macSenderHex, macReceiverHex) {
  const fakeethernetframe = macSenderHex + macReceiverHex + EthType;
  const byteArrayHex = Buffer.from(fakeethernetframe + hexString, 'hex');
  const byteArrayLength = Buffer.alloc(4);
  byteArrayLength.writeInt32LE(byteArrayHex.length);

  ms.write(Buffer.from(time.getTime().toString())); // EPOCH TIME
  ms.write(byteArrayLength); // TIME IN Nani!?!?!?Seconds
  ms.write(byteArrayLength); // FRAME LENGTH
  ms.write(byteArrayHex); // FRAME CONTENT
}

module.exports = { converter };
