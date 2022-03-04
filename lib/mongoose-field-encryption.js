"use strict";

const crypto = require("crypto");

const algorithm = 'aes-256-cbc';
const encryptionHead = '__enc_';
const encryptedDataTag = '_d';

const encrypt = function (clearText, secret, iv) {
  const cipher = crypto.createCipheriv(algorithm,secret,iv);
  const encrypted = cipher.update(clearText);
  const final = cipher.final()
  return Buffer.concat([encrypted,final]).toString('hex');
}

const decrypt = function  ( encrypted, secret, iv) {
  const encryptedBuffer = new Buffer.from(encrypted,'hex')
  const decipher = crypto.createDecipheriv(algorithm,secret,iv);
  const decrypted = decipher.update(encryptedBuffer);
  const final = decipher.final();
  return Buffer.concat([decrypted,final]).toString();
}

const fieldEncryption = function ( schema, options) {
  if(!options || !options.secret) {
    throw new Error('missing required secret');
  }

  const _fields = options.fields || [];
  const _secret = options.secret
  const _iv = 'a2xhcgAAAAAAAAAA';
  // const _iv = options.iv

  for (const field of _fields) {
    const isEncrypted = encryptionHead + field;
    const encryptedData = isEncrypted + encryptedDataTag;
    const schemaField = {};

    schemaField[isEncrypted] = { type: Boolean };
    schemaField[encryptedData] = { type: String };
    schema.add(schemaField)
  }

  //local methods

  //for mongoose 4/5 compatibility
  const defaultNext = function defaultNext(err) {
    if(err) {
      throw err;
    }
  }

  function getCompatibleNextFunc(next) {
    if (typeof next !== "function") {
      return defaultNext;
    }
    return next;
  }

  function getCompatibleData(next, data) {
    // in mongoose5, 'data' field is undefined
    if (!data) {
      return next;
    }
    return data
  }

  function encryptFields ( obj ) {
    for (const field of _fields) {
      const isEncrypted =  encryptionHead + field;
      const encryptedData = isEncrypted + encryptedDataTag;
      const fieldValue = obj[field];

      if(!obj[isEncrypted] && fieldValue) {
        if (typeof fieldValue === "string") {
          //handle strings separately to maintain searchability
          const value = encrypt(fieldValue, _secret, _iv);
          obj[field] = value
        } else {
          const value = encrypt(JSON.stringify(fieldValue), _secret, _iv);
          obj[field] = undefined;
          obj[encryptedData] = value;
        }

        obj[isEncrypted] = true
      }
    }
  }

  function decryptFields(obj) {
    for (const field of _fields) {
      const isEncrypted = encryptionHead + field;
      const encryptedData = isEncrypted + encryptedDataTag;

      if (obj[isEncrypted]) {
        if(obj[encryptedData]) {
          const encryptedValue = obj[encryptedData];

          obj[field] = JSON.parse(decrypt(encryptedValue,_secret,_iv));
          obj[isEncrypted] = false;
          obj[encryptedData] = ""
        }
        else {
          // If the field has beeb marked to not be retrieved, it'll be undefined
          if(obj[field]) {
            // handle strings seperatly to maintain searchability
            const encryptedValue = obj[field];
            obj[field] = decrypt(encryptedValue,_secret,_iv);
            obj[isEncrypted] = false;
          }
        }
        
      }
    }
  }

  function updateHook(_next) {
    const next = getCompatibleNextFunc(_next);
    for (const field of _fields) {
      const isEncrypted = encryptionHead + field;
      this._update.$set = this._update.$set || {};
      const plainValue = this._update.$set[field] || this._update[field];
      const encryptedValue = this._update.$set[isEncrypted] || this._update[isEncrypted];

      if ( !encryptedValue && plainValue) {
        const updateObj= {};
        if(typeof plainValue === "string" ||plainValue instanceof String) {
          const encryptedData = encrypt(plainValue, _secret, _iv)

          updateObj[field] = encryptedData;
          updateObj[isEncrypted] = true;
        }
        else {
          const encryptedData = isEncrypted + encryptedDataTag;

          updateObj[field] = undefined;
          updateObj[encryptedData] = encrypt(JSON.stringify(plainValue),_secret,_iv);
          updateObj[isEncrypted] = true;
        }
        this.update({}, Object.keys(this._update.$set).length > 0 ? {$set: updateObj} : updateObj);
      }
    }

    next();
  }

  /**
   * static methods
   */

  schema.methods.stripEncryptionFieldMakers = function () {
    for (const field of _fields) {
      const isEncrypted = encryptionHead + field;
      const encryptedData = isEncrypted + encryptedDataTag;

      this.set(isEncrypted, undefined);
      this.set(encryptedData, undefined);
    }
  };

  schema.methods.decryptFieldsSync = function () {
    decryptFields(this);
  };

  schema.methods.encryptFieldsSync = function () {
    encryptFields(this)
  };

  /**
   * hooks
   */

  schema.post('init', function ( _next, _data) {
    const next = getCompatibleNextFunc(_next);
    const data = getCompatibleData(_next, _data);
    try {
      decryptFields(data);
      next()
    } catch (e) {
      next(e)
    }
  });

  schema.pre('save', function(_next) {
    const next = getCompatibleNextFunc(_next);

    try {
      encryptFields(this);
      next();
    } catch(e) {
      next(e)
    }
  });

  schema.pre(['findOneAndUpdate','update','updateOne'], updateHook);

  schema.post(['save'], function( _next) {
    const next = getCompatibleNextFunc(_next);
    try {
      decryptFields(this);
      next()
    } catch (e) {
      next(e)
    }
  })

}

module.exports.fieldEncryption = fieldEncryption;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;