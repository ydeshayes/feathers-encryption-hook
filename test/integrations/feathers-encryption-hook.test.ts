const feathers = require('@feathersjs/feathers')

import { Application } from '@feathersjs/feathers'
import hook from '../../src/feathers-encryption-hook'

describe('One field simple encryption tests with encryption config', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    app.set('encryption', {
      key: '*F-JaNdRgUkXp2r5u8x/A?D(G+KbPeSh',
      algorithm: 'aes-256-cbc',
    })

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      before: {
        create: hook({
          algorithm: 'aes-256-cbc',
          fields: ['foo'],
        }),
      },
    })
  })

  it('encrypt the given fields', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.foo).not.toBe('verySensitiveData')
  })

  it('Do nothing to the field bar', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
      bar: 'notVerySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.foo).not.toBe('verySensitiveData')
    expect(resp.bar).toBe('notVerySensitiveData')
  })
})

describe('Simple encrypt/decrypt tests with custom config', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      before: {
        create: hook({
          algorithm: 'aes-256-cbc',
          key: '*F-JaNdRgUkXp2r5u8x/A?D(G+KbPeSh',
          fields: ['foo'],
        }),
      },
      after: {
        create: hook({
          algorithm: 'aes-256-cbc',
          key: '*F-JaNdRgUkXp2r5u8x/A?D(G+KbPeSh',
          fields: ['foo'],
        }),
      },
    })
  })

  it('Do nothing to the field bar', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
      bar: 'notVerySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.bar).toBe('notVerySensitiveData')
  })

  it('encrypt and decrypt the given fields', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.foo).toBe('verySensitiveData')
  })
})

describe('Simple encrypt/decrypt tests with encryption config', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    app.set('encryption', {
      key: '*F-JaNdRgUkXp2r5u8x/A?D(G+KbPeSh',
      algorithm: 'aes-256-cbc',
    })

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      before: {
        create: hook({
          fields: ['foo'],
        }),
      },
      after: {
        create: hook({
          fields: ['foo'],
        }),
      },
    })
  })

  it('Do nothing to the field bar', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
      bar: 'notVerySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.bar).toBe('notVerySensitiveData')
  })

  it('encrypt and decrypt the given fields', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.foo).toBe('verySensitiveData')
  })

  it('encrypt and decrypt the given json fields', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      bar: 'notVerySensitiveData',
      foo: {
        test: 'verySensitiveData',
      },
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp).toHaveProperty('foo')
    expect(resp.foo).toHaveProperty('test')
    expect(resp.foo.test).toBe('verySensitiveData')
  })
})

describe('Simple encrypt/decrypt tests with authentication config', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    app.set('authentication', {
      secret: '*F-JaNdRgUkXp2r5u8x/A?D(G+KbPeSh',
      algorithm: 'aes-256-cfb',
    })

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      before: {
        create: hook({
          fields: ['foo'],
        }),
      },
      after: {
        create: hook({
          fields: ['foo'],
        }),
      },
    })
  })

  it('Do nothing to the field bar', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
      bar: 'notVerySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.bar).toBe('notVerySensitiveData')
  })

  it('encrypt and decrypt the given fields', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.foo).toBe('verySensitiveData')
  })
})

describe('Only decrypt in after hook', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      after: {
        create: hook({
          algorithm: 'aes-256-cbc',
          key: '*F-JaNdRgUkXp2r5u8x/A?D(G+KbPeSh',
          fields: ['foo'],
        }),
      },
    })
  })

  it('Throw error if the field is not encrypted', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'verySensitiveData',
      bar: 'notVerySensitiveData',
    }

    try {
      await app.service('messages').create(data, params)
    } catch (err) {
      let error
      if (err instanceof Error) {
        error = err.toString()
      }
      expect(error).toBe('Error: Bad encrypted value')
    }
  })

  it('Decrypt a already encrypted field', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'WFX9VZYFTlc1aQwsI/qmPg==:HzrbIAfggTSB6vHtGSuaQC1E5eZNaX8M66zBxAogumI=',
      bar: 'notVerySensitiveData',
    }

    const resp = await app.service('messages').create(data, params)

    expect(resp.foo).toBe('verySensitiveData')
  })

  it('Decrypt a already encrypted field', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'WFX9VZYFTlc1aQwsI/qmPHzrbIAfggTSB6vHtGSuaQC1E5eZNaX8M66zBxAogumI=',
      bar: 'notVerySensitiveData',
    }

    let error
    try {
      await app.service('messages').create(data, params)
    } catch (err) {
      if (err instanceof Error) {
        error = err.toString()
      }
    }
    expect(error).toBe('Error: Bad encrypted value')
  })
})

describe('Simple encrypt/decrypt tests without config', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      before: {
        create: hook({
          fields: ['foo'],
        }),
      },
      after: {
        create: hook({
          fields: ['foo'],
        }),
      },
    })
  })

  it('Throw an error', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'WFX9VZYFTlc1aQwsI/qmPg==:HzrbIAfggTSB6vHtGSuaQC1E5eZNaX8M66zBxAogumI=',
      bar: 'notVerySensitiveData',
    }

    let error
    try {
      await app.service('messages').create(data, params)
    } catch (err) {
      if (err instanceof Error) {
        error = err.toString()
      }
    }

    expect(error).toBe('Error: Missing key or algorithm')
  })
})

describe('Simple encrypt/decrypt tests without key', () => {
  let app: Application

  beforeEach(() => {
    app = feathers()

    // Register a dummy custom service that just return the
    // message data back
    app.use('/messages', {
      async create(data) {
        return data
      },
    })

    app.service('messages').hooks({
      before: {
        create: hook({
          algorithm: 'test',
          fields: ['foo'],
        }),
      },
      after: {
        create: hook({
          algorithm: 'test',
          fields: ['foo'],
        }),
      },
    })
  })

  it('Throw an error', async () => {
    const user = { _id: 'test' }
    const params = { user }

    const data = {
      foo: 'WFX9VZYFTlc1aQwsI/qmPg==:HzrbIAfggTSB6vHtGSuaQC1E5eZNaX8M66zBxAogumI=',
      bar: 'notVerySensitiveData',
    }

    let error
    try {
      await app.service('messages').create(data, params)
    } catch (err) {
      if (err instanceof Error) {
        error = err.toString()
      }
    }

    expect(error).toBe('Error: Missing key or algorithm')
  })
})
