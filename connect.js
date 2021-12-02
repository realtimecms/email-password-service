const crypto = require('crypto')

const app = require("@live-change/framework").app()
const definition = require("./definition.js")

const { User, EmailPassword, EmailKey } = require("./model.js")

require('../../i18n/ejs-require.js')
const i18n = require('../../i18n')

definition.action({
  name: "startConnect",
  properties: {
    email: {
      ...EmailPassword.properties.email,
      validation: ['nonEmpty', 'email', 'newUserEmail']
    },
    passwordHash: EmailPassword.properties.passwordHash,
    recaptcha: {
      type: "String",
      singleUse: true,
      validation: ['recaptcha', 'nonEmpty']
    }
  },
  access: (params, { client, service }) => {
    if(!client.user) return false
    return true
  },
  async execute({ email, passwordHash }, {service, client}, emit) {
    const emailPasswordPromise = EmailPassword.get(email)
    const registerKeysPromise = (service.dao.get(['database', 'query', service.databaseName, `(${
        async (input, output, { email }) =>
            await input.table("emailPassword_EmailKey").onChange((obj, oldObj) => {
              if(obj && obj.action == 'register' && !obj.used
                  && obj.email == email && obj.expire > Date.now()) output.put(obj)
            })
    })`, { email }]))
    const randomKeyPromise = new Promise((resolve, reject) => crypto.randomBytes(16, (err, buf) => {
      if(err) reject(err)
      resolve(buf.toString('hex')
          + (crypto.createHash('sha256').update(email).digest('hex').slice(0,8)) )
    }))
    const userRowPromise = User.get(client.user)
    const [emailRow, registerKeys, randomKey, userRow] =
        await Promise.all([emailPasswordPromise, registerKeysPromise, randomKeyPromise, userRowPromise])
    if(emailRow) { /// DON'T REMOVE IT - IT MUST BE REVALIDATED HERE
      if(emailRow.user != client.user) throw "taken"
      throw "alreadyConnected"
    }
    if(registerKeys.length > 0)
      throw "registrationNotConfirmed" /// DON'T REMOVE IT - IT MUST BE REVALIDATED HERE

    const userData = userRow.userData
    const lang = userData.language || Object.keys(i18n.languages)[0]
    const user = client.user
    emit("emailPassword", [{
      type: 'keyGenerated',
      action: 'connect',
      key: randomKey,
      user,
      email, passwordHash,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    const i18nLang = i18n.languages[lang] || i18n()
    await service.trigger({
      type:"sendEmail",
      email: i18nLang.emailPassword.connectEmail({ key: randomKey, email, userData })
    })
  }
})

definition.action({
  name: "finishConnect",
  properties: {
    key: { type: String }
  },
  async execute({ key }, { service, client}, emit) {
    const emailKey = await EmailKey.get(key)
    if(!emailKey) throw 'keyNotFound'
    if(emailKey.action != 'connect') throw 'keyTypeMismatch'
    if(emailKey.used) throw new Error('used')
    if(emailKey.expire < Date.now()) throw 'expired'
    const emailRow = await EmailPassword.get(emailKey.email)
    if(emailRow) throw 'alreadyAdded'
    const { user, email, passwordHash } = emailKey
    emit("emailPassword", [{
      type: "keyUsed",
      key
    }, {
      type: "EmailPasswordCreated",
      emailPassword: email,
      data: {
        user, email, passwordHash
      }
    }])
    emit("users", [{
      type: "loginMethodAdded",
      user,
      method: {
        type: "emailPassword",
        id: email,
        email
      }
    }])
    if(client && client.sessionId) {
      emit("session", [{
        type: "loggedIn",
        user,
        session: client.sessionId,
        expire: null,
        roles: []
      }])
      await service.trigger({
        type: "OnLogin",
        user: user,
        session: client.sessionId
      })
    }
  }
})
