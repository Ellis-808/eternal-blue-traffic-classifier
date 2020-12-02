import {
  DataFrame,
  Series
} from 'pandas-js';

import Config from 'config';
import { parse } from 'pcap-parser';

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
    parser.on('globalHeader', header => {
      console.log(header);
    });
    parser.on('packet', packet => {
      console.log(packet);
      i++;
    });
    parser.on('end', end => {
      console.log("COUNT:", i, "Packets");
      resolve();
    });
  });
}