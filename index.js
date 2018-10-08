/**
 * 加密类 md5/sha1/base64
 * @authors yutent (yutent@doui.cc)
 * @date    2015-09-10 13:56:18
 */

'use strict'

const CRYPTO = require('crypto')
const FS = require('fs')

module.exports = {
  origin: CRYPTO,
  __stamp__: '',
  __inc__: 0,

  hash(mode, data, outEncode) {
    let sum = CRYPTO.createHash(mode)
    let isBuffer = Buffer.isBuffer(data)

    sum.update(data, isBuffer ? 'binary' : 'utf8')
    return sum.digest(outEncode || 'hex')
  },

  hmac(mode, data, key, outEncode) {
    key = key || ''
    let sum = CRYPTO.createHmac(mode, key)
    let isBuffer = Buffer.isBuffer(data)

    sum.update(data, isBuffer ? 'binary' : 'utf8')
    return sum.digest(outEncode || 'hex')
  },

  cipher(mode, data, key, inEncode, outEncode) {
    key = key || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'utf8'
    outEncode = outEncode || 'base64'

    let cp = CRYPTO.createCipher(mode, key)
    let res = cp.update(data, inEncode, outEncode)
    return res + cp.final(outEncode)
  },

  decipher(mode, data, key, inEncode, outEncode) {
    key = key || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'base64'
    outEncode = outEncode || 'utf8'

    let dcp = CRYPTO.createDecipher(mode, key)
    let res = dcp.update(data, inEncode, outEncode)
    return res + dcp.final(outEncode)
  },

  cipheriv(mode, data, key, iv, inEncode, outEncode) {
    key = key || '0000000000000000'
    iv = iv || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'utf8'
    outEncode = outEncode || 'base64'

    let cp = CRYPTO.createCipheriv(mode, key, iv)
    let res = cp.update(data, inEncode, outEncode)
    return res + cp.final(outEncode)
  },

  decipheriv(mode, data, key, iv, inEncode, outEncode) {
    key = key || '0000000000000000'
    iv = iv || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'base64'
    outEncode = outEncode || 'utf8'

    let dcp = CRYPTO.createDecipheriv(mode, key, iv)
    let res = dcp.update(data, inEncode, outEncode)
    return res + dcp.final(outEncode)
  },

  /**
   * [rand 生成指定长度的随机字符串]
   * @param  {[type]} len      [要得到的字符串长度]
   * @param  {[type]} forceNum [是否强制返回纯数字]
   */
  rand(len, forceNum) {
    let str = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789'
    if (forceNum) {
      str = '0123456789'
    }
    let max = str.length
    let tmp = ''
    for (let i = 0; i < len; i++) {
      let r = Math.floor(Math.random() * max)
      tmp += str[r]
    }
    return tmp
  },

  // 返回一个如下格式的 xxxxxxxx-xxxx-xxxx-xxxxxxxx 的唯一ID
  uuid() {
    let rand = CRYPTO.randomBytes(8).toString('hex')
    let now = (Date.now() / 1000).toString(16).slice(0, 8)
    if (this.__stamp__ === now) {
      this.__inc__++
    } else {
      this.__stamp__ = now
      this.__inc__ = 0
    }
    rand = this.__inc__.toString(16) + rand

    rand = rand.slice(0, 4) + '-' + rand.slice(4, 8) + '-' + rand.slice(8, 16)
    return this.__stamp__ + '-' + rand
  },

  /**
   * [md5 md5加密]
   * @param  {Str/Num} str    [要加密的字符串]
   * @param  {Str} encode [hex/base64]
   */
  md5(str, encode) {
    if (typeof str === 'number') {
      str += ''
    }
    if (typeof str !== 'string' && !Buffer.isBuffer(str)) {
      return str
    }

    return this.hash('md5', str, encode)
  },

  /**
   * [md5Sign 获取文件的md5签名]
   * @param  {Str} file [文件路径]
   */
  md5Sign(file) {
    if (!fs.existsSync(file)) {
      return null
    }

    let fileStream = fs.readFileSync(file)
    return this.hash('md5', fileStream)
  },

  /**
   * [sha1 sha1加密]
   * @param  {Str/Num} str    [要加密的字符串]
   * @param  {Str} encode [hex/base64]
   */
  sha1(str, encode) {
    if (typeof str === 'number') {
      str += ''
    }
    if (typeof str !== 'string' && !Buffer.isBuffer(str)) {
      return str
    }

    return this.hash('sha1', str, encode)
  },

  /**
   * [sha1Sign 获取文件的sha1签名]
   * @param  {Str} file [文件路径]
   */
  sha1Sign(file) {
    if (!fs.existsSync(file)) {
      return null
    }

    let fileStream = fs.readFileSync(file)
    return this.hash('sha1', fileStream)
  },

  /**
   * [sha256 sha256加密]
   * @param  {Str/Num} str    [要加密的字符串]
   * @param  {Str} encoding [hex/base64]
   */
  sha256(str, encoding) {
    if (typeof str === 'number') {
      str += ''
    }
    if (typeof str !== 'string' && !Buffer.isBuffer(str)) {
      return str
    }

    return this.hash('sha256', str, encoding)
  },

  /**
   * [base64encode base64加密]
   * @param  {Str/Num/Buffer} str         [要加密的字符串]
   * @param  {bool} urlFriendly [是否对URL友好，默认否，是则会把+转成-，/转成_]
   */
  base64encode(str, urlFriendly) {
    if (!Buffer.isBuffer(str)) {
      str = Buffer.from(str + '')
    }
    let encode = str.toString('base64')
    if (urlFriendly) {
      return encode
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
    }
    return encode
  },

  /**
   * [base64decode base64解密]
   * @param  {Str} str         [要解密的字符串]
   * @param  {bool} urlFriendly [之前是否对结果采用了URL友好处理]
   * @param  {Str/Buffer} encoding    [编码，默认utf-8]
   */
  base64decode(str, urlFriendly, encoding) {
    if (urlFriendly) {
      str = str
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .replace(/[^A-Za-z0-9\+\/]/g, '')
    }

    let buff = Buffer.from(str, 'base64')

    if (encoding === 'buffer') {
      return buff
    }

    return buff.toString(encoding || 'ascii')
  }
}
