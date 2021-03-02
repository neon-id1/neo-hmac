const MD5 = require('crypto-js/md5')
const crypto = require('crypto')

class HMACSignature {
    _createHash(request, APIContext, timestamp) {
        const { body, method } = request
        const js = JSON.stringify(body)
        const jsc =  js.replace(/\s+/g, '')
        const MD5jsc = MD5(jsc).toString()
        const rw = `${timestamp}:${APIContext.key}:${method}:${MD5jsc}`
        return crypto.createHmac('sha256', APIContext.secret).update(rw).digest('base64')
    }

    async validate(request, APIContext) {
        try {
            const { headers } = request
            const ts = new Date(headers.timestamp)
            const hash = this._createHash(request, APIContext, ts)
            return hash === headers.hash;
        } catch (error) {
            console.log(error)
            return false
        }
    }

    async createSignature(request, APIContext) {
        try {
            const ts = new Date()
            return this._createHash(request, APIContext, ts)
        } catch (error) {
            console.log(error)
            return null
        }

    }
}

module.exports = HMACSignature