/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import util from '@ohos.util';
import cryptoFramework from '@ohos.security.cryptoFramework';
import Logger from './Logger';


const TAG: string = '[CipherModel]'
const AES128: string = 'AES128';
const AES128_CBC_PKCS5: string = 'AES128|CBC|PKCS5';
const AES128_PKCS7: string = 'AES128|PKCS7';

export class CipherModel {
  stringToUint8Array(str) {
    var arr = [];
    for (var i = 0, j = str.length; i < j; ++i) {
      arr.push(str.charCodeAt(i));
    }
    var tmpArray = new Uint8Array(arr);
    return tmpArray;
  }

  uint8ArrayToString(array: Uint8Array) {
    let arrayString = '';
    for (let i = 0; i < array.length; i++) {
      arrayString += String.fromCharCode(array[i]);
    }
    return arrayString;
  }

  aesEncrypt(message: string, key: string, iv: string, callback) {
    let that = new util.Base64Helper();

    let paramsSpec: cryptoFramework.IvParamsSpec = { iv: { data: this.stringToUint8Array(iv) }, algName: "IvParamsSpec" }
    let aesGenerator = cryptoFramework.createSymKeyGenerator(AES128);
    let cipher = cryptoFramework.createCipher(AES128_CBC_PKCS5);
    let pubKey = that.decodeSync(key);
    let pubKeyBlob: cryptoFramework.DataBlob = { data: pubKey };
    aesGenerator.convertKey(pubKeyBlob, (err, symKey) => {
      if (err) {
        console.error("convertKey: error.");
        return;
      }
      cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, symKey, paramsSpec, (err, data) => {
        let input: cryptoFramework.DataBlob = { data: this.stringToUint8Array(message) };
        cipher.doFinal(input, (err, data) => {
          Logger.info(TAG, "EncryptOutPut is " + data.data);
          let result = that.encodeToStringSync(data.data)
          Logger.info(TAG, "result is " + result);
          callback(result)
        })
      })
    })
  }

  aesDecrypt(message: string, key: string, iv: string, callback) {
    let paramsSpec: cryptoFramework.IvParamsSpec = { iv: { data: this.stringToUint8Array(iv) }, algName: "IvParamsSpec" }

    let aesGenerator = cryptoFramework.createSymKeyGenerator(AES128);
    let cipher = cryptoFramework.createCipher(AES128_CBC_PKCS5);
    let that = new util.Base64Helper();
    let pubKey = that.decodeSync(key);
    let pubKeyBlob: cryptoFramework.DataBlob = { data: pubKey };
    aesGenerator.convertKey(pubKeyBlob, (err, symKey) => {
      if (err) {
        console.error("convertKey: error.");
        return;
      }
      cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, symKey, paramsSpec, (err, data) => {
        let newMessage = that.decodeSync(message);
        let input: cryptoFramework.DataBlob = { data: newMessage };
        cipher.doFinal(input, (err, data) => {
          Logger.info(TAG, "DecryptOutPut is " + data.data);
          let result = this.uint8ArrayToString(data.data)
          Logger.info(TAG, "result is " + result);
          callback(result)
        })
      })
    })
  }
}