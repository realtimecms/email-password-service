const crypto = require('crypto')
const rtcms = require("realtime-cms")
const definition = require("./definition.js")

require('../../i18n/ejs-require.js')
const i18n = require('../../i18n')

const {User, EmailPassword, EmailKey} = require("./model.js")

const passwordHash = require("./passwordHash.js")

definition.action({
  name: "updatePasswordByUser",
  properties: {
    email: { type: EmailPassword, idOnly: true },
    oldPasswordHash: { type: String, preFilter: passwordHash },
    newPasswordHash: { type: String, preFilter: passwordHash }
  },
  async execute({ email, oldPasswordHash, newPasswordHash }, { service, client }, emit) {
    if(!client.user) throw new service.error("notAuthorized")
    const user = client.user
    let row = await EmailPassword.get(email)
    if (!row) throw service.error("notFound")
    if (row.user != user) throw service.error("notAuthorized")
    if(row.passwordHash != oldPasswordHash) throw service.error("wrongPassword")

    service.trigger({
      type: "OnPasswordChange",
      user,
      passwordHash: newPasswordHash
    })
  }
})

definition.action({
  name: "updateAllPasswordsByUser",
  properties: {
    oldPasswordHash: { type: String, preFilter: passwordHash },
    newPasswordHash: { type: String, preFilter: passwordHash }
  },
  async execute({ oldPasswordHash, newPasswordHash }, { service, client}, emit) {
    if(!client.user) throw new service.error("notAuthorized")
    const user = client.user
    let cursor = await EmailPassword.run(EmailPassword.table.filter({user}))
    if(!cursor) service.error("notFound")
    let results = await cursor.toArray()
    if(results.length == 0) throw service.error("notFound")
    for(let row of results) {
      if (row.user != user) throw service.error("notAuthorized")
      if (row.passwordHash != oldPasswordHash) throw service.error("wrongPassword")
    }
    service.trigger({
      type: "OnPasswordChange",
      user,
      passwordHash: newPasswordHash
    })
  }
})

definition.action({
  name: "startPasswordReset",
  properties: {
    email: { type: EmailPassword, idOnly: true }
  },
  async execute({ email }, { service, client}, emit) {
    let userPromise = EmailPassword.run(EmailPassword.table.get(email).do(
        e => User.table.get(e('user'))
    ))
    let randomKeyPromise = new Promise((resolve, reject) => crypto.randomBytes(16, (err, buf) => {
      if(err) reject(err)
      resolve(buf.toString('hex')+(crypto.createHash('sha256').update(email).digest('hex').slice(0,8)))
    }))
    let [user, randomKey] = await Promise.all([userPromise, randomKeyPromise])
    emit("emailPassword", [{
      type: 'keyGenerated',
      action: 'resetPassword',
      email, user: user.id,
      key: randomKey,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    emit("email", [{
      type: "sent",
      email: i18n().emailPassword.resetPasswordEmail({email, key: randomKey, user})
    }])
  }
})

definition.action({
  name: "finishPasswordReset",
  properties: {
    key: { type: String },
    newPasswordHash: { type: String, preFilter: passwordHash }
  },
  async execute({ key, newPasswordHash }, { service, client}, emit) {
    let emailKey = await EmailKey.get(key)
    if(!emailKey) throw service.error('notFound')
    if(emailKey.action != 'resetPassword') throw service.error('notFound')
    if(emailKey.used) throw service.error('used')
    if(emailKey.expire < Date.now()) throw service.error('expired')
    let emailRow = await EmailPassword.get(emailKey.email)
    if(!emailRow) throw service.error('notFound')
    service.trigger({
      type: "OnPasswordChange",
      user: emailRow.user,
      passwordHash: newPasswordHash
    })
    emit("emailPassword", [{
      type: "keyUsed",
      key
    }])
  }
})


definition.event({
  name: "userPasswordChanged",
  properties: {
    user: {
      type: User,
      idOnly: true
    }
  },
  async execute({ user, passwordHash }) {
    let cursor = await EmailPassword.run(EmailPassword.table.filter({user}))
    if(!cursor) service.error("notFound")
    let results = await cursor.toArray()
    if(results.length == 0) throw service.error("notFound")
    for(let row of results) {
      EmailPassword.update(row.email, { passwordHash })
    }
  }
})

definition.trigger({
  name: "OnPasswordChange",
  properties: {
    user: {
      type: User,
      idOnly: true
    },
    passwordHash: {
      type: String
    }
  },
  async execute({ user, passwordHash }, context, emit) {
    emit([{
      type: "userPasswordChanged",
      user,
      passwordHash
    }])
  }
})

