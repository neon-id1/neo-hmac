import crypto from 'crypto'
import { Request } from 'express'

function _createHash(request: Request, APIContext:any , timestamp: Date) {
    const { body, method } = request
    const js = JSON.stringify(body)
    const jsc =  js.replace(/\s+/g, '')
    const MD5jsc = crypto.createHash('md5').update(jsc).digest("hex");
    const rw = `${JSON.stringify(timestamp)}:${APIContext.key}:${method}:${MD5jsc}`
    return crypto.createHmac('sha256', APIContext.secret).update(rw).digest('base64')
}

export function validate(input: Input) {
    try {
        const { headers } = input.request
        const ts = new Date(headers.timestamp as string)
        const hash = _createHash(input.request, input.APIContext, ts)
        return hash === headers.signature;
    } catch (error) {
        console.log(error)
        return false
    }
}

export function createSignature(input: Input) {
    try {
        const ts = new Date()
        return {
            signature: _createHash(input.request, input.APIContext, ts),
            timestamp: ts
        }
    } catch (error) {
        console.log(error)
        return null
    }
}

export interface Input {
    request: Request
    APIContext: APIContext
}

export interface APIContext {
    secret: string
    key: string
}