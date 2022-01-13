const crypto = require('crypto')
const ReactiveDao = require("@live-change/dao")

const app = require("@live-change/framework").app()
const definition = require("./definition.js")

const { User, EmailPassword, EmailKey } = require("./model.js")

const passwordHash = require('../config/passwordHash.js')
const userData = require('../config/userData.js')(definition)
const userDataDefinition = userData

require('../../i18n/ejs-require.js')
const i18n = require('../../i18n')

let propertiesWithoutEmail = {}
for(let propName in userData.field.properties) {
  if(propName == 'email') continue;
  propertiesWithoutEmail[propName] = userData.field.properties[propName]
}
let userDataWithoutEmail = {
  ...userData.field,
  properties: propertiesWithoutEmail
}

definition.action({
  name: "startRegister",
  properties: {
    ...userData.registerFields,
    email: {
      ...EmailPassword.properties.email,
      validation: ['nonEmpty', 'email', 'newUserEmail']
    },
    passwordHash: EmailPassword.properties.passwordHash,
    userData: userDataWithoutEmail,
    recaptcha: {
      type: "String",
      singleUse: true,
      validation: ['recaptcha', 'nonEmpty']
    },
    lang: { type: String, validation: ['nonEmpty'] }
  },
  draft: {
    steps: userData.registerSteps
  },
  async execute({ email, passwordHash, userData, lang }, {service, client}, emit) {
    let emailPasswordPromise = EmailPassword.get(email)
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
    let randomKeyPromise = new Promise((resolve, reject) => crypto.randomBytes(16, (err, buf) => {
      if(err) reject(err)
      resolve(buf.toString('hex')
          + (crypto.createHash('sha256').update(email).digest('hex').slice(0,8)) )
    }))
    const [emailRow, registerKeys, randomKey] =
        await Promise.all([emailPasswordPromise, registerKeysPromise, randomKeyPromise])
    if(emailRow) throw "alreadyAdded" /// DON'T REMOVE IT - IT MUST BE REVALIDATED HERE
    if(registerKeys.length > 0)
      throw "registrationNotConfirmed" /// DON'T REMOVE IT - IT MUST BE REVALIDATED HERE
    const user = app.generateUid()
    emit("emailPassword", [{
      type: 'keyGenerated',
      action: 'register',
      key: randomKey,
      user,
      email, passwordHash, userData: { ...userData, email: email },
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    const i18nLang = i18n.languages[lang] || i18n()
    await service.trigger({
      type:"sendEmail",
      email: i18nLang.emailPassword.registerEmail({ key: randomKey, email, userData })
    })
    await service.trigger({
      type:"OnRegisterStart",
      session: client.sessionId,
      user: user
    })
  }
})

definition.action({
  name: "resendRegisterKey",
  properties: {
    email: EmailPassword.properties.email,
    lang: { type: String, validation: ['nonEmpty'] }
  },
  async execute({email, lang}, {service}, emit) {
    const emailHash = crypto.createHash('sha1').update(email).digest('hex')
    const registerKeys = await (service.dao.get(['database', 'query', service.databaseName, `(${
      async (input, output, { emailHash }) => {
        const index = await input.index("emailPassword_EmailKey_byEmailHashAction")
        const prefix = `${emailHash}:register_`
        await index.range({ gt: prefix, lt: prefix+'\xFF' }).onChange((obj, oldObj) => {
          if(obj) output.debug("OBJ", obj, 'E', obj.expire, ">", Date.now(), '=>', obj.expire > Date.now())
          if(obj && obj.expire > Date.now()) output.put(obj)
        })
      }
    })`, { emailHash }]))
    if(registerKeys.length == 0) throw 'notFound'
    const registerKey = await EmailKey.get(registerKeys[0].to)
    if(!registerKey) throw 'notFound'
    emit("emailPassword", [{
      type: 'keyProlonged',
      key: registerKey.key,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    const i18nLang = i18n.languages[lang] || i18n()
    await service.trigger({
      type:"sendEmail",
      email: i18nLang.emailPassword.registerEmail({ key: registerKey.key, email, userData: registerKey.userData})
    })
  }
})

definition.action({
  name: "finishRegister",
  properties: {
    key: { type: String },
    //sessionId: { type: String } - from clientData
  },
  async execute({ key }, {service, client}, emit) {
    let registerKeyRow = await EmailKey.get(key)
    if(!registerKeyRow) throw 'notFound'
    if(registerKeyRow.expire < Date.now()) throw 'expired'
    if(registerKeyRow.used) throw new Error('used')
    let emailRow = await EmailPassword.get(registerKeyRow.email)
    if(emailRow) throw 'alreadyAdded'
    let {user, email, passwordHash, userData} = registerKeyRow
    userData.email = email
    const slug = await (userDataDefinition.createSlug ?
        userDataDefinition.createSlug(registerKeyRow, service)
        : service.triggerService('slugs', {
          type: "CreateSlug",
          group: "user",
          to: user
        })
    )
    await service.triggerService('slugs', {
      type: "TakeSlug",
      group: "user",
      path: user,
      to: user,
      redirect: slug
    })
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
      type: "UserCreated",
      user,
      data: {
        userData,
        slug,
        display: await userDataDefinition.getDisplay({ userData })
      }
    },{
      type: "loginMethodAdded",
      user,
      method: {
        type: "emailPassword",
        id: email,
        email
      }
    }])
    await service.trigger({
      type: "OnRegister",
      session: client.sessionId,
      user: user,
      userData
    })
    if(client && client.sessionId) emit("session", [{
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
    await service.trigger({
      type: "OnRegisterComplete",
      session: client.sessionId,
      user: user,
      userData
    })
    return user
  }
})


