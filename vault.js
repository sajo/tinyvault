'use strict';
const isBrowser = typeof window !== 'undefined' && window.hasOwnProperty('Window') && window instanceof window.Window;
const crypto = isBrowser ? window.crypto : require('crypto');
const envault = {'ID': 0, 'IV': 1, 'SALT': 2, 'SEED': 3, 'BODY': 4, 'PEPPER': 5, 'EXTRA': 6, 'USER': 7, 'PASS': 8};
/**
 * Class
 * @module Vault
 */
class Vault {
  /**
 * Constructor
 * @param {object} data - Vault content
 * @param {number} iterations - Iterations to protect against brute force
 * @param {number} pbkdf2Sizebits - Number of bits or size of key
 * @param {String} mode - Algorithm to encrypt the first layer'AES-CBC' or 'AES-GCM'
 * @param {String} hash - Algorithm to derive key 'SHA-256' or 'SHA-512'
 */
  constructor(data = {}, iterations = 100000, pbkdf2Sizebits = 256, mode = 'AES-CBC', hash = 'SHA-256') {
    this.data = data;
    this.iterations = iterations;
    this.pbkdf2Sizebits = pbkdf2Sizebits;
    this.mode = mode;
    this.hash = hash;
  }
  /**
 * This function only generate random bytes in hex resizable
 * @param    {number} y
 * @return  {String} - Return in hex string
 */
  static #rand = (y) => crypto.getRandomValues(new Uint8Array(y))
      .reduce((sum, x, i) => {
        return sum + ((i === 0) ? x|1 : x).toString(16).padStart(2, '0');
      }, '');

  /**
 * This function only convert string to buffer
 * @param    {String} str - Function to convert password into buffer
 * @return  {Buffer} - Return in hex string
 */
  static #strToBuf = (str) => (new TextEncoder().encode(str));
  /**
 * This function derive a key to resizable output, this is used by encryption
 * @param   {String} rawKey - Password as string converted to buffer
 * @param   {Buffer} cSalt - Function to convert password into buffer
 * @param   {number} cIterations - Iterations to protect against brute force
 * @param   {number} size - Number of bits or size of key output
 * @param   {String} hash - Algorithm to derive key 'SHA-256' or 'SHA-512'
 * @return  {Buffer} - Return in hex string
 */
  static async #pbkdf2(rawKey, cSalt, cIterations, size, hash) {
    const key = await crypto.subtle.importKey(
        'raw',
        Vault.#strToBuf(rawKey),
        'PBKDF2',
        false,
        ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      hash: hash,
      salt: Vault.#hexToBuf(cSalt),
      iterations: cIterations,
    }, key, size);
    return bits;
  }

  /**
 * This function encrypt with AES CBC/GCM/CTR
 * @param   {Buffer} derkey - Key derived with PBKDF2
 * @param   {object} configEnc - This var only store configurations about AES
 * @param   {object} data - Vault content
 * @return  {Buffer} - Buffer with Vault
 */
  static async #encrypt(derkey, configEnc, data) {
    const key = await crypto.subtle.importKey('raw', derkey,
        {name: configEnc['name']}, false, ['encrypt']);
    const encData = await crypto.subtle.encrypt(configEnc, key, data)
        .then((buf) => new Uint8Array(buf));
    return encData;
  }
  /**
 * This function decrypt AES CBC/GCM/CTR
 * @param   {Buffer} derkey - Key derived with PBKDF2
 * @param   {object} configEnc - This var only store configurations about AES
 * @param   {object} data -  Vault content
 * @return  {Buffer} - Buffer with Vault
 */
  static async #decrypt(derkey, configEnc, data) {
    const bufKey = await crypto.subtle.importKey('raw', derkey,
        {name: configEnc['name']}, false, ['decrypt']);
    const decData = await crypto.subtle.decrypt(configEnc, bufKey, data)
        .then((buf) => new Uint8Array(buf));
    return decData;
  }
  /**
 * Convert buffer to HEX
 * @param   {Buffer} buf - Data as buffer
 * @return  {hexString} - Only a data as hex
 */
  static #bufToHex = (buf) => {
    const byteArray = new Uint8Array(buf);
    let hexString = '';
    let nextHexByte;
    for (let i=0; i<byteArray.byteLength; i++) {
      nextHexByte = byteArray[i].toString(16);
      if (nextHexByte.length < 2) {
        nextHexByte = '0' + nextHexByte;
      }
      hexString += nextHexByte;
    }
    return hexString;
  };

  /**
 * Convert buffer to HEX
 * @param   {hexString} hex - Only a data as hex
 * @return  {Buffer} -  Data as buffer
 */
  static #hexToBuf = (hex) => {
    let bytes;
    let c;
    for (bytes = [], c = 0; c < hex.length; c += 2) {
      bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return new Uint8Array(bytes);
  };
  /**
 * Convert buffer to String
 * @param   {Buffer} str - Data as buffer
 * @return  {String} -   Only a data as String
 */
  static #bufToStr = (str) => (new TextDecoder().decode(str));
  /**
 * The main function to create a new password manager
 * @param   {String} rawKey - The raw key as String
 * @return  {Object} -   The content vault as Buffer Object
 */
  async generate(rawKey) {
    this.data = {};
    Object.assign(this.data, {[envault['ID']]: Vault.#rand(4)});
    Object.assign(this.data, {[envault['IV']]: Vault.#rand(16)});
    Object.assign(this.data, {[envault['SALT']]: Vault.#rand(4)});
    const configEnc = {name: this.mode,
      iv: Vault.#hexToBuf(this.data[[envault['IV']]])};
    const derkey = await Vault.#pbkdf2(rawKey,
        this.data[[envault['SALT']]],
        this.iterations,
        this.pbkdf2Sizebits,
        this.hash);
    const SEED = await Vault.#encrypt(derkey, configEnc,
        Vault.#hexToBuf(Vault.#rand(14)));
    Object.assign(this.data, {[envault['SEED']]: Vault.#bufToHex(SEED)});
    Object.assign(this.data, {[envault['BODY']]: []});
    return this.data;
  }
  /**
 * Function to add a new pass into the password manager
 * @param   {String} rawKey - The raw key as String
 * @param   {Object} dataVault - Buffer Object with content of vault
 * @param   {String} extraData - URL, Host, etc.
 * @param   {String} user - Nickname, email, etc.
 * @param   {String} newPass - The raw key as String
 * @return  {Object} -   The content vault as Buffer Object
 */
  async addPass(rawKey, dataVault, extraData, user, newPass) {
    this.data = dataVault;
    const newData = {};
    const derkey = await Vault
        .#pbkdf2(
            rawKey,
            this.data[[envault['SALT']]],
            this.iterations,
            this.pbkdf2Sizebits,
            this.hash,
        );

    let configEnc = {name: this.mode, iv: Vault.#hexToBuf(this.data[[envault['IV']]])};
    const SEED = await Vault.#decrypt(derkey, configEnc, Vault.#hexToBuf(this.data[[envault['SEED']]]));
    Object.assign(newData, {[envault['PEPPER']]: Vault.#rand(3)});

    let derIV = await Vault.#pbkdf2(SEED, newData[[envault['PEPPER']]], this.iterations, 128, this.hash);
    configEnc = {name: this.mode, iv: derIV};
    extraData = await Vault.#encrypt(derkey, configEnc, Vault.#strToBuf(extraData));
    Object.assign(newData, {[envault['EXTRA']]: Vault.#bufToHex(extraData)});

    derIV = await Vault.#pbkdf2(SEED, newData[[envault['PEPPER']]], this.iterations+1, 128, this.hash);
    configEnc = {name: this.mode, iv: derIV};
    user = await Vault.#encrypt(derkey, configEnc, Vault.#strToBuf(user));
    Object.assign(newData, {[envault['USER']]: Vault.#bufToHex(user)});

    derIV = await Vault.#pbkdf2(SEED, newData[[envault['PEPPER']]], this.iterations+2, 128, this.hash);
    configEnc = {name: this.mode, iv: derIV};

    configEnc = {name: 'AES-CTR', counter: derIV, length: newPass.length};
    const ENC_PASS = await Vault.#encrypt(derkey, configEnc, Vault.#strToBuf(newPass));
    Object.assign(newData, {[envault['PASS']]: Vault.#bufToHex(ENC_PASS)});
    // Processing new vault
    Object.assign(this.data, {[envault['BODY']]: [{...newData}, ...this.data[[envault['BODY']]]]});
    return this.data;
  }

  /**
 * Function to view the password manager
 * @param   {String} rawKey - The raw key as String
 * @param   {Object} dataVault - Buffer Object with content of vault
 * @return  {Object} -   The content vault as Buffer Object
 */
  async viewPass(rawKey, dataVault) {
    const vaultDecrypted = {};
    const uniqueData = {};
    Object.assign(vaultDecrypted, {[envault['BODY']]: []});
    this.data = dataVault;
    let configEnc = {name: this.mode, iv: Vault.#hexToBuf(this.data[[envault['IV']]])};
    const derkey = await Vault
        .#pbkdf2(rawKey, Vault.#hexToBuf(
            this.data[[envault['SALT']]]), this.iterations, this.pbkdf2Sizebits, this.hash,
        );
    const SEED = await Vault.#decrypt(derkey, configEnc, Vault.#hexToBuf(this.data[[envault['SEED']]]));

    for (const item of this.data[[envault['BODY']]]) {
      Object.assign(uniqueData, {'ID': item[[envault['PEPPER']]]});
      let derIV = await Vault.#pbkdf2(SEED,
          item[[envault['PEPPER']]],
          this.iterations, 128, this.hash);
      configEnc = {name: this.mode, iv: derIV};

      const extradata = await Vault.#decrypt(derkey, configEnc, Vault.#hexToBuf(item[[envault['EXTRA']]]));
      Object.assign(uniqueData, {'EXTRA': Vault.#bufToStr(extradata)});

      derIV = await Vault.#pbkdf2(SEED, item[[envault['PEPPER']]], this.iterations+1, 128, this.hash);
      configEnc = {name: this.mode, iv: derIV};
      const user = await Vault.#decrypt(derkey, configEnc, Vault.#hexToBuf(item[[envault['USER']]]));
      Object.assign(uniqueData, {'USER': Vault.#bufToStr(user)});

      derIV = await Vault.#pbkdf2(SEED, item[[envault['PEPPER']]], this.iterations+2, 128, this.hash);
      configEnc = {name: 'AES-CTR', counter: derIV, length: Vault.#hexToBuf(item[[envault['PASS']]]).length};
      const decPass = await Vault.#decrypt(derkey, configEnc, Vault.#hexToBuf(item[[envault['PASS']]]));
      Object.assign(uniqueData, {'PASS': Vault.#bufToStr(decPass)});
      Object.assign(vaultDecrypted, {[envault['BODY']]: [{...uniqueData}, ...vaultDecrypted[[envault['BODY']]]]});
    }

    return vaultDecrypted;
  }
  /**
 * Function to remove empty fields from Vault
 * @param   {Object} obj - Vault to clean and remove empty fields
 * @return  {Object} -   The content vault as Buffer Object
 */
  static #cleanEmpty = (obj) => {
    if (Array.isArray(obj)) {
      return obj
          .map((v) => (v && typeof v === 'object') ? Vault.#cleanEmpty(v) : v)
          .filter((v) => !(v == null));
    } else {
      return Object.entries(obj)
          .map(([k, v]) => [k, v && typeof v === 'object' ? Vault.#cleanEmpty(v) : v])
          .reduce((a, [k, v]) => (v == null ? a : (a[k]=v, a)), {});
    }
  };
  /** Function to remove a password from Vault
* @param   {string} id - ID password to remove
* @param   {object} dataVault - Vault content
* @return  {Object} - Return in hex string
*/
  async dellPass(id, dataVault) {
    for (let i = 0; i < dataVault[[envault['BODY']]].length; i++) {
      if (id == dataVault[[envault['BODY']]][i][5]) {
        delete dataVault[[envault['BODY']]][i];
      }
    }
    dataVault[[envault['BODY']]] = Vault.#cleanEmpty(dataVault[[envault['BODY']]]);
    return dataVault;
  }
};

if (!isBrowser) {
  module.exports = Vault;
}
