#!/usr/bin/env node
const process = require('process');
const fs = require('fs');
const msgpack = require('@msgpack/msgpack');
const Vault = require('../vault.js');

const args = process.argv.slice(2)
    .map((arg) => arg.split(/[=]/))
    .reduce((args, [value, key]) => {
      args[value.split('-').join('')] = key;
      return args;
    }, {});

const cofre = new Vault();

switch (args.mode) {
  case 'generate':
    if (!(['mode' && 'password'] in args)) break;
    cofre.generate(args.password).then((dataVault) => {
      const encoded = msgpack.encode(dataVault);
      fs.writeFile('./vault.dat', encoded, 'binary', (err)=>{
        if (err) console.log(err);
        else console.log('Generated password vault');
      });
    });

    break;

  case 'addpass':
    if (!(['mode' && 'password' && 'extra' && 'user' && 'newpass'] in args)) {
      break;
    }
    binary = fs.readFileSync('./vault.dat');
    cofre.addPass(
        args.password,
        msgpack.decode(binary),
        args.extra,
        args.user,
        args.newpass).then((dataVault) => {
      fs.writeFile('./vault.dat', msgpack.encode(dataVault), 'binary', (err)=>{
        if (err) console.log(err);
        else console.log('New pass added');
      });
    });

    break;

  case 'viewpass':
    if (!(['mode' && 'password'] in args)) break;
    binary = fs.readFileSync('./vault.dat');
    cofre.viewPass(args.password, msgpack.decode(binary))
        .then((dataVault) => {
          console.log(dataVault);
        });

    break;

  case 'dellpass':
    if (!(['mode' && 'idpass'] in args)) break;
    binary = fs.readFileSync('./vault.dat');
    cofre.dellPass(args.idpass, msgpack.decode(binary)).then((dataVault) => {
      fs.writeFile('./vault.dat', msgpack.encode(dataVault), 'binary', (err)=>{
        if (err) console.log(err);
        else console.log('Generated password vault');
      });
    });
    break;

  case (args.help) || (args.h):
    const log = console.log;
    log('tinyvault -mode=generate -password=');
    log('tinyvault -mode=addpass -password= -extra= -user= -newpass=');
    log('tinyvault -mode=viewpass -password=');
    log('tinyvault -mode=dellpass -idpass=<idAvailable@vault>');
    break;
  default:
    console.log('Something wrong, type argument -h or --help!');
}
