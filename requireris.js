const crypto = require('crypto'),
      base32 = require('thirty-two'),
      express = require('express'),
      app = express();
      server = require('http').createServer(app),
      ent = require('ent'),
      fs = require('fs');
let   io = require('socket.io');

function hotp(secret, count) {

  let counter = Buffer.alloc(8);

  secret = base32.decode(secret);

  const hmac = crypto.createHmac('sha1', secret);

  counter.writeUIntBE(count, 0, 8);

  hmac.update(counter);

  function truncate(HS) {
    let offset = HS[19] & 0xf;
    let bin_code = (HS[offset]  & 0x7f) << 24
             | (HS[offset+1] & 0xff) << 16
             | (HS[offset+2] & 0xff) <<  8
             | (HS[offset+3] & 0xff);

    let truncatedValue = (bin_code % Math.pow(10, 6));

    return ("000000" + truncatedValue).slice(-6);
  }

  let HS = hmac.digest();
  let SBits = truncate(HS);
  return SBits;
}

app.get('/', function (req, res) {
  res.sendfile(__dirname + '/index.html');
});

app.use(express.static('public'));

server.listen(4242);

io = io.listen(server);

io.sockets.on('connection', function(socket) {
  socket.on('totp_asking', function(secret) {
    let result = hotp(secret, Date.now() / 30000);

    socket.emit('hotp_response', result);
  });

  socket.on('hotp_asking', function(secret, count) {
    let result = hotp(secret, count);

    socket.emit('hotp_response', result);
  });
});

console.log('The server is listening on http://localhost:4242');
