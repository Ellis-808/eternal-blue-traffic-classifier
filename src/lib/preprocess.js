import {
  DataFrame,
  Series
} from 'pandas-js';

const fs = require('fs');

export function preProcessPcap(malewareType) {
  if(typeof malewareType !== 'string')
    throw new Error("parameter `malwareType` must be of type string");
  
  // On second thought...NO!
  let file;
  if(malewareType.toLowerCase() === 'eternalblue')
    file = fs.readFileSync("data/EternalBlue/eternalblue-success-unpatched-win7.pcap");
  else if(malewareType.toLowerCase() === 'petya')
    file = fs.readFileSync("");
}