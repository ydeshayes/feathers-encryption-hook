import { HookContext } from '@feathersjs/feathers'

import { encrypt as encryptFct, decrypt as decryptFct, tryToParseJSON } from './utils'

export interface EncryptOptions {
  key?: string
  algorithm?: string
  fields: string[]
}

export default (options: EncryptOptions) =>
  async function encrypt(context: HookContext): Promise<HookContext> {
    const algorithm =
      options.algorithm ||
      context.app.get('encrytion')?.algorithm ||
      context.app.get('authentication')?.algorithm
    const key =
      options.key || context.app.get('encrytion')?.key || context.app.get('authentication')?.secret

    if (!algorithm || !key) {
      throw Error('Missing key or algorithm')
    }

    for (let i = 0; i < options.fields.length; i++) {
      const field = options.fields[i]

      if (context.type === 'before') {
        context.data[field] = encryptFct(algorithm, key, JSON.stringify(context.data[field]))
      } else if (context.type === 'after') {
        context.result[field] = tryToParseJSON(decryptFct(algorithm, key, context.result[field]))
      }
    }

    return context
  }
