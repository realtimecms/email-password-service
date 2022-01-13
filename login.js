const definition = require("./definition.js")

const { User, EmailPassword, EmailKey } = require("./model.js")

const passwordHash = require("../config/passwordHash.js")
const crypto = require("crypto")

definition.action({
  name: "login",
  properties: {
    email: EmailPassword.properties.email,
    passwordHash: EmailPassword.properties.passwordHash,
  },
  autoSecurity: true,
  async execute({ email, passwordHash }, {service, client}, emit) {
    const emailHash = crypto.createHash('sha1').update(email).digest('hex')
    const registerKeysPromise = (service.dao.get(['database', 'query', service.databaseName, `(${
        async (input, output, { emailHash }) => {
          const index = await input.index("emailPassword_EmailKey_byEmailHashAction")
          const prefix = `${emailHash}:register_`
          await index.range({ gt: prefix, lt: prefix+'\xFF' }).onChange((obj, oldObj) => {
            if(obj) output.debug("OBJ", obj, 'E', obj.expire, ">", Date.now(), '=>', obj.expire > Date.now())
            if(obj && obj.expire > Date.now()) output.put(obj)
          })
        }
    })`, { emailHash }]))
    let emailPasswordPromise = EmailPassword.get(email)
    let [registerKeys, emailPasswordRow] = await Promise.all([registerKeysPromise, emailPasswordPromise])
    if(!emailPasswordRow && registerKeys.length > 0) throw "registrationNotConfirmed"
    if (!emailPasswordRow) {
      await service.trigger({
        type: "securityEvent",
        event: {
          type: "login-failed",
          keys: { ip: client.ip, session: client.sessionId, user: client.user }
        }
      })
      throw "notFound"
    }
    if(emailPasswordRow.passwordHash != passwordHash) {
      await service.trigger({
        type: "securityEvent",
        event: {
          type: "login-failed",
          keys: { ip: client.ip, session: client.sessionId, user: client.user }
        }
      })
      throw "wrongPassword"
    }
    let userRow = await User.get(emailPasswordRow.user)
    if(!userRow) throw new Error("internalServerError")
    emit("session", [{
      type: "loggedIn",
      user: emailPasswordRow.user,
      session: client.sessionId,
      expire: null,
      roles: userRow.roles || []
    }])
    await service.trigger({
      type: "OnLogin",
      user: emailPasswordRow.user,
      session: client.sessionId
    })
  }
})
