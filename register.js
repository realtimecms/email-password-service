const crypto = require('crypto')

const rtcms = require("realtime-cms")
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

definition.action({
  name: "startRegister",
  properties: {
    email: EmailPassword.properties.email,
    passwordHash: EmailPassword.properties.passwordHash,
    userData,
    recaptcha: {
      type: "String",
      validation: ['recaptcha']
    }
  },
  async execute({ email, passwordHash, userData }, {service, client}, emit) {
    let emailPasswordPromise = EmailPassword.get(email)
    let registerKeysPromise = EmailKey.run(EmailKey.table
        .filter({ action: 'register',  used: false, email })
        .filter(r=>r("expire").gt(Date.now()))
    ).then(cursor => {
          if(!cursor) return []
          return cursor.toArray()
        })
    let randomKeyPromise = new Promise((resolve, reject) => crypto.randomBytes(16, (err, buf) => {
      if(err) reject(err)
      resolve(buf.toString('hex')+(crypto.createHash('sha256').update(email).digest('hex').slice(0,8)))
    }))
    const [emailRow, registerKeys, randomKey] =
        await Promise.all([emailPasswordPromise, registerKeysPromise, randomKeyPromise])
    if(emailRow) throw service.error("alreadyAdded")
    //console.log("HOW?!!", email, emailRow)
    if(registerKeys.length>0) throw service.error("registrationNotConfirmed")
    const user = rtcms.generateUid()
    emit("emailPassword", [{
      type: 'keyGenerated',
      action: 'register',
      key: randomKey,
      user,
      email, passwordHash, userData: { ...userData, email: email },
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    emit("email", [{
      type: "sent",
      email: i18n().emailPassword.registerEmail({ key: randomKey, email, userData })
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
    email: { type: String }
  },
  async execute({email}, {service}, emit) {
    let registerKey = await EmailKey.run(EmailKey.table
        .filter({ action: 'register',  used: false, email })
        .filter(r => r("expire").gt(Date.now()))
    ).then(cursor => {
      if(!cursor) return [];
      return cursor.toArray().then( arr => arr[0] );
    })
    if(!registerKey) throw new evs.error("notFound")
    emit("emailPassword", [{
      type: 'keyProlonged',
      key: registerKey.key,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    emit("email", [{
      type: "sent",
      email: i18n().emailPassword.registerEmail({ key: registerKey.key, email, userData: registerKey.userData})
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
    if(!registerKeyRow) throw service.error('notFound')
    if(registerKeyRow.expire < Date.now()) throw service.error('expired')
    if(registerKeyRow.used) throw service.error('used')
    let emailRow = await EmailPassword.get(registerKeyRow.email)
    if(emailRow) throw evs.error('alreadyAdded')
    let {user, email, passwordHash, userData} = registerKeyRow
    userData.email = email
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
        userData
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
  async read({ key }, cd, method) {
    if(method == "get") return EmailKey.table.get(key).without('passwordHash')
    return EmailKey.table.get(key).changes({includeInitial: true})
        .without({new_val: "passwordHash", old_val: "passwordHash"})
  }
})
