const crypto = require('crypto')

class HMACSignature {
    _createHash(request, APIContext, timestamp) {
        const { body, method } = request
        const js = JSON.stringify(body)
        const jsc =  js.replace(/\s+/g, '')
        const MD5jsc = crypto.createHash('md5').update(jsc).digest("hex");
        const rw = `${timestamp}:${APIContext.key}:${method}:${MD5jsc}`
        return crypto.createHmac('sha256', APIContext.secret).update(rw).digest('base64')
    }

    validate(request, APIContext) {
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

    createSignature(request, APIContext) {
        try {
            const ts = new Date()
            return {
                signature: this._createHash(request, APIContext, ts),
                timestamp: ts
            }
        } catch (error) {
            console.log(error)
            return null
        }

    }
}

module.exports = HMACSignature