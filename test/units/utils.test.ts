import { encrypt, decrypt, tryToParseJSON } from '../../src/utils'

describe('Crypto fonctions', () => {
  it('Encrypt and decrypt correctly', () => {
    const algorithm = 'aes-256-cbc'
    const key = 'z%C*F-JaNcRfUjXn2r5u8x/A?D(G+KbP'
    const encrypted = encrypt(algorithm, key, 'testValue')

    expect(encrypted).not.toBe('testValue')

    const decrypted = decrypt(algorithm, key, encrypted)

    expect(decrypted).toBe('testValue')
  })

  it('Encrypt and decrypt empty value correctly', () => {
    const algorithm = 'aes-256-cbc'
    const key = 'z%C*F-JaNcRfUjXn2r5u8x/A?D(G+KbP'
    const encrypted = encrypt(algorithm, key, '')

    expect(encrypted).not.toBe('testValue')

    const decrypted = decrypt(algorithm, key, encrypted)

    expect(decrypted).toBe('')
  })
})

describe('JSON fonctions', () => {
  it('Parse not json value', () => {
    const notJSON = tryToParseJSON('test')

    expect(notJSON).toBe('test')
  })

  it('Parse not json value', () => {
    const json = tryToParseJSON('{"foo": "bar"}')

    expect(json).toHaveProperty('foo')
    expect(json.foo).toBe('bar')
  })
})
