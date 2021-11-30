const definition = require("./definition.js")

const User = definition.foreignModel("users", "User")

const passwordHash = require('../config/passwordHash.js')
const ReactiveDao = require("@live-change/dao")

const userData = require('../config/userData.js')(definition)

const EmailPassword = definition.model({
  name: "EmailPassword",
  /// TODO: add queued by email
  properties: {
    email: {
      type: String,
      preFilter: email => email.toLowerCase(),
      validation: ['nonEmpty', 'email']
    },
    passwordHash: {
      type: String,
      secret: true,
      preFilter: passwordHash,
      validation: userData.passwordValidation || ['nonEmpty', 'safePassword']
    },
    user: {
      type: User
    }
  },
  indexes: {
    byUser: {
      property: "user"
    }
  },
  crud: {
    options: {
      access: (params, {client, service, visibilityTest}) => {
        return client.roles.includes('admin')
      }
    }
  }
})

const EmailKey = definition.model({
  name: "EmailKey",
  properties: {
    action: { type: String },
    used: { type: Boolean, defaultValue: false },
    email: { type: String },
    expire: { type: Number }
  }
})

definition.event({
  name: "keyGenerated",
  async execute(data) {
    EmailKey.create({
      ...data,
      id: data.key
    })
  }
})

definition.event({
  name: "keyProlonged",
  async execute({ key, expire }) {
    EmailKey.update(key, { expire })
  }
})

definition.event({
  name: "keyUsed",
  async execute({ key }) {
    EmailKey.update(key, { used: true })
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
    return obj && { ...obj, passwordHash: undefined }
  },
  observable({ key }, { service }) {
    const keyObservable = service.dao.observable(
        ['database', 'tableObject', service.databaseName, 'emailPassword_EmailKey', key])
    const outObservable = new ReactiveDao.ObservableValue(keyObservable.value)
    const observer = (signal, value) => {
      if(signal != 'set') return outObservable.error("unknownSignal")
      outObservable.set(value && { ...value, passwordHash: undefined })
    }
    const oldDispose = outObservable.dispose
    const oldRespawn = outObservable.respwan
    outObservable.dispose = () => {
      keyObservable.unobserve(observer)
      oldDispose.call(outObservable)
    }
    outObservable.respawn = () => {
      keyObservable.observe(observer)
      oldRespawn.call(outObservable)
    }
    keyObservable.observe(observer)
    return outObservable
  }
})

module.exports = {
  User, EmailPassword, EmailKey
}