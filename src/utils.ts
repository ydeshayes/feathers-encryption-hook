const crypto = require('crypto')

export function encrypt(algorithm: string, key: string, value: string) {
  if (!value) {
    return ''
  }

  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv(algorithm, key, iv)

  return `${iv.toString('base64')}:${cipher.update(value, 'utf8', 'base64')}${cipher.final(
    'base64'
  )}`
}

export function decrypt(algorithm: string, key: string, encryptedValue: string) {
  if (!encryptedValue) {
    return ''
  }

  const ivAndEncrypt = encryptedValue.split(':')

  if (ivAndEncrypt.length < 2) {
    throw Error('Bad encrypted value')
  }
  const iv = Buffer.from(ivAndEncrypt[0], 'base64')
  const decipher = crypto.createDecipheriv(algorithm, key, iv)

  return `${decipher.update(ivAndEncrypt[1], 'base64', 'utf8')}${decipher.final('utf8')}`
}

export function tryToParseJSON(value: string) {
  try {
    return JSON.parse(value)
  } catch {
    return value
  }
}
