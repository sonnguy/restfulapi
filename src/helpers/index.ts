import crypto from "crypto";

const SECRET_KEY = "SON.NGUY92"

export const random = () => crypto.randomBytes(128).toString('base64');

export const authentication = (salt: string, password:string) => {
    return crypto.createHmac('sha256', [salt, password].join('/')).update(SECRET_KEY).digest('hex')
};

