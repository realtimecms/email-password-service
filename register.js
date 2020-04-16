const crypto = require('crypto')
const ReactiveDao = require("@live-change/dao")

const app = require('./app.js')
const definition = require("./definition.js")

const {User, EmailPassword, EmailKey} = require("./model.js")

const passwordHash = require('../config/passwordHash.js')
const userData = require('../config/userData.js')(definition)

require('../../i18n/ejs-require.js')
const i18n = require('../../i18n')

definition.event({
  name: "keyGenerated",
  async execute(data) {
    EmailKey.create({
      ...data,
      id: data.key
    })
  }
})

let propertiesWithoutEmail = {}
for(let propName in userData.properties) {
  if(propName == 'email') continue;
  propertiesWithoutEmail[propName] = userData.properties[propName]
}
let userDataWithoutEmail = {
  ...userData,
  properties: propertiesWithoutEmail
}

definition.action({
  name: "startRegister",
  properties: {
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
    const registerKeysPromise = (service.dao.get(['database', 'query', service.databaseName, `(${
        async (input, output, { email }) =>
            await input.table("emailPassword_EmailKey").onChange((obj, oldObj) => {
              if(obj && obj.action == 'register' && !obj.used
                  && obj.email == email && obj.expire > Date.now()) output.put(obj)
            })
    })`, { email }]))
    let randomKeyPromise = new Promise((resolve, reject) => crypto.randomBytes(16, (err, buf) => {
      if(err) reject(err)
      resolve(buf.toString('hex')+(crypto.createHash('sha256').update(email).digest('hex').slice(0,8)))
    }))
    const [emailRow, registerKeys, randomKey] =
        await Promise.all([emailPasswordPromise, registerKeysPromise, randomKeyPromise])
    if(emailRow) throw new Error("alreadyAdded") /// DON'T REMOVE IT - IT MUST BE REVALIDATED HERE
    if(registerKeys.length>0)
      throw new Error("registrationNotConfirmed") /// DON'T REMOVE IT - IT MUST BE REVALIDATED HERE
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
    emit("email", [{
      type: "sent",
      email: i18nLang.emailPassword.registerEmail({ key: randomKey, email, userData })
    }])
    await service.trigger({
      type:"OnRegisterStart",
      session: client.sessionId,
      user: user
    })
  }
})

definition.event({
  name: "keyProlonged",
  async execute({ key, expire }) {
    EmailKey.update(key, { expire })
  }
})

definition.action({
  name: "resendRegisterKey",
  properties: {
    email: EmailPassword.properties.email,
    lang: { type: String, validation: ['nonEmpty'] }
  },
  async execute({email, lang}, {service}, emit) {
    const registerKey = await (service.dao.get(['database', 'query', service.databaseName, `(${
        async (input, output, { email }) =>
            await input.table("emailPassword_EmailKey").onChange((obj, oldObj) => {
              if(obj && obj.action == 'register' && !obj.used
                  && obj.email == email && obj.expire > Date.now()) output.put(obj)
            })
    })`, { email }]).then(v => v && v[0]))
    if(!registerKey) throw new new Error("notFound")
    emit("emailPassword", [{
      type: 'keyProlonged',
      key: registerKey.key,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    const i18nLang = i18n.languages[lang] || i18n()
    emit("email", [{
      type: "sent",
      email: i18nLang.emailPassword.registerEmail({ key: registerKey.key, email, userData: registerKey.userData})
    }])
  }
})

definition.event({
  name: "keyUsed",
  async execute({ key }) {
    EmailKey.update(key, { used: true })
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
    if(!registerKeyRow) throw new Error('notFound')
    if(registerKeyRow.expire < Date.now()) throw new Error('expired')
    if(registerKeyRow.used) throw new Error('used')
    let emailRow = await EmailPassword.get(registerKeyRow.email)
    if(emailRow) throw new Error('alreadyAdded')
    let {user, email, passwordHash, userData} = registerKeyRow
    userData.email = email
    const slug = await service.triggerService('slugs', {
      type: "CreateSlug",
      group: "user",
      to: user
    })
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
        slug
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
      type:"OnRegister",
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
    return user
  }
})

definition.view({
  name: "emailKey",
  properties: {
    key: {
      type: EmailKey,
      idOnly: true
    }
  },
  returns: {
    type: EmailKey
  },
  rawRead: true,
  async get({ key }, { service }) {
    const obj = await service.dao.get(['database', 'tableObject', service.databaseName, 'emailPassword_EmailKey', key])
    return { ...obj, passwordHash: null }
  },
  observable({ key }, { service }) {
    const keyObservable = service.dao.observable(['database', 'tableObject', service.databaseName,
      'emailPassword_EmailKey', key])
    const outObservable = new ReactiveDao.ObservableValue(keyObservable.value)
    const observer = (signal, value) => {
      if(signal != 'set') return outObservable.error("unknownSignal")
      outObservable.set(value && { ...value, passwordHash: null })
    }
    const oldDispose = outObservable.dispose
    const oldRespawn = outObservable.respwan
    outObservable.dispose = () => {
      keyObservable.unobserve(observer)
      oldDispose.call(outObservable)
    }
    outObservable.respwan = () => {
      keyObservable.observe(observer)
      oldRespawn.call(outObservable)
    }
    return outObservable
  }
})
