const fs = require('fs');
const path = require('path');
const { converter } = require('./converter');

async function main() {
  let args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('please specify in the args the path of log file');
    return;
  }

  if (args.length > 1) {
    console.log('there are too much args');
    return;
  }

  if (!fs.existsSync(args[0])) {
    console.log('the log file doesn\'t exist');
    return;
  }

  const txt = fs.readFileSync(args[0], 'utf-8');

  const ms = converter(txt);

  if(ms === null) {
    console.log('error');
    return;
  }

  await saveToDisk(ms, path.join(process.cwd(), path.basename(args[0], path.extname(args[0])) + '.pcap'));
}

async function saveToDisk(ms, filePath) {
  const ws = fs.createWriteStream(filePath);
  ws.write(ms.read());
  ws.end();
}

main();