/**
 * 加密类 md5/sha1/base64
 * @author yutent<yutent.io@gmail.com>
 * @date 2020/09/16 18:11:51
 */

const os = require('os')
const fs = require('fs')
const Helper = require('./lib/helper.js')

const MAC = (function(ns) {
  for (let k in ns) {
    let _ = ns[k].pop()
    if (_.mac !== '00:00:00:00:00:00') {
      return _.mac
    }
  }
  return process.pid.toString(16) + process.ppid.toString(16)
})(os.networkInterfaces())

var __inc__ = 1024

/**
 * [base64encode base64编码]
 * @param  {Str/Num/Buffer} str         [要编码的字符串]
 * @param  {bool} urlFriendly [是否对URL友好，默认否，是则会把+转成-，/转成_]
 */
Helper.base64encode = function(str, urlFriendly) {
  var buf, str64

  if (Buffer.isBuffer(str)) {
    buf = str
  } else {
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
Helper.base64decode = function(str, urlFriendly) {
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
Helper.rand = function(len, forceNum) {
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
Helper.uuid = function(pipe = '-') {
  var rand = Helper.origin.randomBytes(8).toString('hex')
  var now = (~~(Date.now() / 1000)).toString(16)
  var str

  __inc__++
  if (__inc__ > 65535) {
    __inc__ = 1024
  }
  str = md5(MAC + rand + __inc__)

  return (
    now + pipe + str.slice(0, 4) + pipe + str.slice(4, 8) + pipe + str.slice(-8)
  )
}

/**
 * [md5 md5加密]
 * @param  {Str/Num} str    [要加密的字符串]
 * @param  {Str} encode [hex/base64]
 */
Helper.md5 = function(str, encode) {
  if (typeof str === 'number') {
    str += ''
  }
  if (typeof str === 'string' || Buffer.isBuffer(str)) {
    return Helper.hash('md5', str, encode)
  }

  return str
}

/**
 * [md5Sign 获取文件的md5签名]
 * @param  {Str} file [文件路径]
 */
Helper.md5Sign = function(file) {
  if (fs.accessSync(file, fs.constants.R_OK)) {
    var buf = fs.readFileSync(file)
    return Helper.hash('md5', buf)
  }
  return null
}

/**
 * [sha1 sha1加密]
 * @param  {Str/Num} str    [要加密的字符串]
 * @param  {Str} encode [hex/base64]
 */
Helper.sha1 = function(str, encode) {
  if (typeof str === 'number') {
    str += ''
  }
  if (typeof str === 'string' || Buffer.isBuffer(str)) {
    return Helper.hash('sha1', str, encode)
  }

  return str
}

/**
 * [sha1Sign 获取文件的sha1签名]
 * @param  {Str} file [文件路径]
 */
Helper.sha1Sign = function(file) {
  if (fs.accessSync(file, fs.constants.R_OK)) {
    var buf = fs.readFileSync(file)
    return Helper.hash('sha1', buf)
  }
  return null
}

/**
 * [sha256 sha256加密]
 * @param  {Str/Num} str    [要加密的字符串]
 * @param  {Str} encoding [hex/base64]
 */
Helper.sha256 = function(str, encoding) {
  if (typeof str === 'number') {
    str += ''
  }
  if (typeof str === 'string' || Buffer.isBuffer(str)) {
    return Helper.hash('sha256', str, encoding)
  }

  return str
}

/**
 * [sha256Sign 获取文件的sha256签名]
 * @param  {Str} file [文件路径]
 */
Helper.sha256Sign = function(file) {
  if (fs.accessSync(file, fs.constants.R_OK)) {
    var buf = fs.readFileSync(file)
    return Helper.hash('sha256', buf)
  }
  return null
}

module.exports = Helper
