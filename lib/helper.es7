import crypto from 'crypto'

const GCM_MODE = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm']

export default {
  origin: crypto,

  hash(mode, data, outEncode) {
    let sum = crypto.createHash(mode)
    let isBuffer = Buffer.isBuffer(data)

    sum.update(data, isBuffer ? 'binary' : 'utf8')
    return sum.digest(outEncode || 'hex')
  },

  hmac(mode, data, key, outEncode) {
    key = key || ''
    let sum = crypto.createHmac(mode, key)
    let isBuffer = Buffer.isBuffer(data)

    sum.update(data, isBuffer ? 'binary' : 'utf8')
    return sum.digest(outEncode || 'hex')
  },

  cipher(mode, data, key, inEncode, outEncode) {
    key = key || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'utf8'
    outEncode = outEncode || 'base64'

    let cc = crypto.createCipher(mode, key)
    let enStr = cc.update(data, inEncode, outEncode)
    enStr += cc.final(outEncode)
    if (GCM_MODE.indexOf(mode) > -1) {
      let authTag = cc.getAuthTag()
      return { enStr: enStr, authTag: authTag }
    }
    return enStr
  },

  decipher(mode, data, key, tag, inEncode, outEncode) {
    key = key || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'base64'
    outEncode = outEncode || 'utf8'

    let cd = crypto.createDecipher(mode, key)
    if (GCM_MODE.indexOf(mode) > -1) {
      cd.setAuthTag(tag)
    }
    let deStr = cd.update(data, inEncode, outEncode)
    deStr += cd.final(outEncode)
    return deStr
  },

  cipheriv(mode, data, key, iv, inEncode, outEncode) {
    key = key || '0000000000000000'
    iv = iv || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'utf8'
    outEncode = outEncode || 'base64'

    let cciv = crypto.createCipheriv(mode, key, iv)
    let enStr = cciv.update(data, inEncode, outEncode)
    enStr += cciv.final(outEncode)
    if (GCM_MODE.indexOf(mode) > -1) {
      let authTag = cciv.getAuthTag()
      return { enStr: enStr, authTag: authTag }
    }
    return enStr
  },

  decipheriv(mode, data, key, iv, tag, inEncode, outEncode) {
    key = key || '0000000000000000'
    iv = iv || ''
    let isBuffer = Buffer.isBuffer(data)
    inEncode = isBuffer ? 'binary' : inEncode || 'base64'
    outEncode = outEncode || 'utf8'

    let dcpiv = crypto.createDecipheriv(mode, key, iv)
    if (GCM_MODE.indexOf(mode) > -1) {
      dcpiv.setAuthTag(tag)
    }
    let deStr = dcpiv.update(data, inEncode, outEncode)
    deStr += dcpiv.final(outEncode)
    return deStr
  }
}
