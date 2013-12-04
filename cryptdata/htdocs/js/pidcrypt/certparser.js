function certParser(cert){
    cert = cert.replace(/\r/g,'#cr#');
    cert = cert.replace(/#cr#\n/g,'\n');
    cert = cert.replace(/#cr#/g,'\n');
    var lines = cert.split('\n');
    var read = false;
    var b64 = false;
    var end = false;
    var flag = '';
    var retObj = {};
    retObj.info = '';
    retObj.salt = '';
    retObj.iv;
    retObj.b64 = '';
    retObj.aes = false;
    retObj.mode = '';
    retObj.bits = 0;
    for(var i=0; i< lines.length; i++){
        flag = lines[i].substr(0,9);
        switch(flag){
            case '-----BEGI':
                read = true;
              break;
            case 'Proc-Type':
                if(read)
                    retObj.info = lines[i];
              break;
            case 'DEK-Info:':
                if(read){
                    var tmp = lines[i].split(',');
                    var dek = tmp[0].split(': ');
                    var aes = dek[1].split('-');
                    retObj.aes = (aes[0] == 'AES')?true:false;
                    retObj.mode = aes[2];
                    retObj.bits = parseInt(aes[1]);
                    retObj.salt = tmp[1].substr(0,16);
                    retObj.iv = tmp[1];
                }
               break;
             case '':
                 if(read)
                     b64 = true;
               break;
             case '-----END ':
                 if(read){
                     b64 = false;
                     read = false;
                 }
               break;
             default:
                 if(read && b64)
                     retObj.b64 += lines[i];
        }
    }
  return retObj;
}
