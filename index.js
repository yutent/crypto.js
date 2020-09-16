/**
 * 加密类 md5/sha1/base64
 * @author yutent<yutent.io@gmail.com>
 * @date 2020/09/16 18:11:51
 */

const fs = require('fs')
const Helper = require('./lib/helper.js')

var __stamp__ = ''
var __inc__ = 1024

/**
 * [base64encode base64编码]
 * @param  {Str/Num/Buffer} str         [要编码的字符串]
 * @param  {bool} urlFriendly [是否对URL友好，默认否，是则会把+转成-，/转成_]
 */
exports.base64encode = function(str, urlFriendly) {
  var buf, str64

  if (!Buffer.isBuffer(str)) {
    buf = Buffer.from(str + '')
  }
  str64 = buf.toString('base64')

  if (urlFriendly) {
    return str64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
  }
  return str64
}

/**
 * [base64decode base64解码, 返回Buffer对象]
 * @param  {Str} str         [要解码的字符串]
 * @param  {bool} urlFriendly [之前是否对结果采用了URL友好处理]
 */
exports.base64decode = function(str, urlFriendly) {
  if (urlFriendly) {
    str = str
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/[^A-Za-z0-9\+\/]/g, '')
  }
  return Buffer.from(str, 'base64')
}

/**
 * [rand 生成指定长度的随机字符串]
 * @param  {[type]} len      [要得到的字符串长度]
 * @param  {[type]} forceNum [是否强制返回纯数字]
 */
exports.rand = function(len, forceNum) {
  let str = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789'
  if (forceNum) {
    str = '0123456789'
  }
  let max = str.length
  let tmp = ''
  for (let i = 0; i < len; i++) {
    let r = (Math.random() * max) >> 0
    tmp += str[r]
  }
  return tmp
}

// 返回一个如下格式的 xxxxxxxx-xxxx-xxxx-xxxxxxxx 的唯一ID
exports.uuid = function(pipe = '') {
  var rand = Helper.origin.randomBytes(8).toString('hex')
  var now = ~~(Date.now() / 1000).toString(16)
  var inc

  if (__stamp__ === now) {
    __inc__++
  } else {
    __stamp__ = now
    __inc__ = 1024
  }
  inc = __inc__.toString(16).padStart(4, '0')

  return (
    __stamp__ + pipe + inc + pipe + rand.slice(0, 4) + pipe + rand.slice(-8)
  )
}

/**
 * [md5 md5加密]
 * @param  {Str/Num} str    [要加密的字符串]
 * @param  {Str} encode [hex/base64]
 */
exports.md5 = function(str, encode) {
  if (typeof str === 'number') {
    str += ''
  }
  if (typeof str !== 'string' && !Buffer.isBuffer(str)) {
    return str
  }

  return Helper.hash('md5', str, encode)
}

/**
 * [md5Sign 获取文件的md5签名]
 * @param  {Str} file [文件路径]
 */
exports.md5Sign = function(file) {
  if (!fs.existsSync(file)) {
    return null
  }

  var buf = fs.readFileSync(file)
  return Helper.hash('md5', buf)
}

/**
 * [sha1 sha1加密]
 * @param  {Str/Num} str    [要加密的字符串]
 * @param  {Str} encode [hex/base64]
 */
exports.sha1 = function(str, encode) {
  if (typeof str === 'number') {
    str += ''
  }
  if (typeof str !== 'string' && !Buffer.isBuffer(str)) {
    return str
  }

  return Helper.hash('sha1', str, encode)
}

/**
 * [sha1Sign 获取文件的sha1签名]
 * @param  {Str} file [文件路径]
 */
exports.sha1Sign = function(file) {
  if (!fs.existsSync(file)) {
    return null
  }

  var buf = fs.readFileSync(file)
  return Helper.hash('sha1', buf)
}

/**
 * [sha256 sha256加密]
 * @param  {Str/Num} str    [要加密的字符串]
 * @param  {Str} encoding [hex/base64]
 */
exports.sha256 = function(str, encoding) {
  if (typeof str === 'number') {
    str += ''
  }
  if (typeof str !== 'string' && !Buffer.isBuffer(str)) {
    return str
  }

  return Helper.hash('sha256', str, encoding)
}

/**
 * [sha256Sign 获取文件的sha256签名]
 * @param  {Str} file [文件路径]
 */
exports.sha256Sign = function(file) {
  if (!fs.existsSync(file)) {
    return null
  }

  var buf = fs.readFileSync(file)
  return Helper.hash('sha256', buf)
}

module.exports = Helper
