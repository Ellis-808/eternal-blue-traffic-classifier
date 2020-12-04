import {
  DataFrame,
  Series
} from 'pandas-js';

import Config from 'config';
import { parse } from 'pcap-parser';

const decoders = require('cap').decoders;

/**
 * Connection link types
 * @see {@link http://www.tcpdump.org/linktypes.html Link Types} for more information
 */
const LINK_TYPE = Object.freeze({
  ETHERNET: 1, // LAN
  IEEE802_11: 105 // Wi-Fi
});

/**
 * Create SMB packet
 * 
 * @see {@link https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f SMB Header} for more info
 * @param {Buffer} b Binary data buffer
 * @param {Number} offset Byte offset
 */
function SMB(b, offset) {
  offset || (offset = 0);  
  let orig_offset = offset;
  const header = {
    info: {
      protocol: undefined,
      command: undefined,
      status: undefined,
      flags: undefined,
      flags2: undefined,
      pidHigh: undefined,
      securityFeatures: undefined,
      reserved: undefined,
      tid: undefined,
      pidLow: undefined,
      uid: undefined,
      mid: undefined
    },
    hdrlen: 32, // byte
    offset: offset + 36
  }

  // '\xFF' is interpreted as 4 bytes
  header.info.protocol = b.toString('binary', offset, offset+8).slice(5);
  offset+=8

  header.info.command = b.readUIntBE(offset, 1);
  offset+=1;

  header.info.status = b.readUInt32BE(offset, true);
  offset+=4;

  header.info.flags = b.readUIntBE(offset, 1);
  offset+=1;

  header.info.flags2 = b.readUIntBE(offset, 2);
  offset+=2;

  header.info.pidHigh = b.readUInt16BE(offset, true);
  offset+=2;

  // Bytes get messup up here... wrong data from here on out
  header.info.securityFeatures = b.readBigUInt64BE(offset, true);
  offset+=8;

  header.info.reserved = b.readUInt16BE(offset, true);
  offset+=2;

  header.info.tid = b.readUInt16BE(offset, true);
  offset+=2;

  header.info.pidLow = b.readUInt16BE(offset, true);
  offset+=2;

  header.info.uid = b.readUInt16BE(offset, true);
  offset+=2;

  header.info.mid = b.readUInt16BE(offset, true);
  offset+=2;

  return header;
}

/**
 * Preprocess any malware files inside the data folder
 * @param {String} malewareType Malware to pre-process
 */
export function preProcessPcap(malewareType) {
  if(typeof malewareType !== 'string')
    throw new Error("parameter `malwareType` must be of type string");
  malewareType = malewareType.toLowerCase();

  return new Promise( (resolve, reject) => {
    let parser;
    switch(malewareType) {
      case 'eternal-blue':
        parser = parse(Config.get('eternal-blue'));
        break;
      case 'petya':
        parser = parse(Config.get('petya'));
        break;
      default: throw new Error("invalid malware type");
    }

    let i = 0;
    let globalHeader;
    let smbPackets = {}; // dictionary of SMB packets

    parser.on('globalHeader', header => {
      globalHeader = header;
    });
    parser.on('packet', packet => {
      // ETHERNET
      if(globalHeader.linkLayerType === LINK_TYPE.ETHERNET) {
        let decoded = decoders.Ethernet(packet.data);

        if(decoded.info.type === decoders.PROTOCOL.ETHERNET.IPV4) {
          decoded = decoders.IPV4(packet.data, decoded.offset);

          if(decoded.info.protocol == decoders.PROTOCOL.IP.TCP) {
            let dataLen = decoded.info.totallen - decoded.hdrlen;
            decoded = decoders.TCP(packet.data, decoded.offset);
            dataLen -= decoded.hdrlen;
            // console.log(decoded);
            const packetInfo = packet.data.toString('binary', decoded.offset, decoded.offset + dataLen);
            if(packetInfo.toLowerCase().includes("smb") && i <= 0) {
              console.log("TCP-Packet:", packetInfo);
              console.log("PACKET", decoded);
              decoded = SMB(packet.data, decoded.offset);
              console.log("SMB-Packet:", decoded);
              console.log(packet);
              i++;
            }
          }

        }
      }
    });
    parser.on('end', end => {
      console.log(globalHeader);
      resolve();
    });
  });
}