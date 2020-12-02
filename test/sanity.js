import DetectMalware from '../src/lib/classify';
import { preProcessPcap } from '../src/lib/preprocess';

describe("detect-malware", function() {
  this.timeout(60000);

  it('preprocess', done => {
    preProcessPcap("eternal-blue").then( () => {
      done();
    });
  });
});