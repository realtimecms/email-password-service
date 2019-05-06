const crypto = require('crypto')
const rtcms = require("realtime-cms")
const definition = require("./definition.js")

const {User, EmailPassword, EmailKey} = require("./model.js")

require('../../i18n/ejs-require.js')
const i18n = require('../../i18n')

definition.action({
  name: "startEmailChange",
  properties: {
    user: { type: User, idOnly: true },
    newEmail: { type: String },
    passwordHash: { type: String }
  },
  async execute({ user, newEmail, passwordHash }, {client, service}, emit) {
    let oldEmailPromise = EmailPassword.run(EmailPassword.table.filter({ user }).nth(0))
    let newEmailPromise = EmailPassword.get(newEmail)
    let randomKeyPromise = new Promise((resolve, reject) => crypto.randomBytes(16, (err, buf) => {
      if(err) reject(err)
      resolve(buf.toString('hex')+(crypto.createHash('sha256').update(user + newEmail).digest('hex').slice(0,8)))
    }))
    let userPromise = User.get(user)
    let [oldEmailRow, newEmailRow, randomKey, userRow] =
        await Promise.all([oldEmailPromise, newEmailPromise, randomKeyPromise, userPromise])
    if(!oldEmailRow) throw service.error('notFound')
    if(newEmailRow) throw service.error('taken')
    if(oldEmailRow.user != user) throw service.error('notAuthorized')
    if(oldEmailRow.passwordHash != passwordHash) throw service.error('wrongPassword')
    let oldEmail = oldEmailRow.email
    emit("emailPassword", [{
      type: 'keyGenerated',
      action: 'emailChange',
      oldEmail, newEmail, user,
      key: randomKey,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    }])
    emit("email", [{
      type: "sent",
      email: i18n().emailPassword.changeEmailEmail({oldEmail, newEmail, key: randomKey, user: userRow})
    }])
  }
})

definition.action({
  name: "finishEmailChange",
  properties: {
    key: { type: String }
  },
  async execute({ key }, {client, service}, emit) {
    let emailKey = await EmailKey.get(key)
    if(!emailKey) throw service.error('notFound')
    if(emailKey.action != 'emailChange') throw service.error('notFound')
    if(emailKey.used) throw service.error('used')
    if(emailKey.expire < Date.now()) throw service.error('expired')
    let oldEmailPromise = EmailPassword.get(emailKey.oldEmail)
    let newEmailPromise = EmailPassword.get(emailKey.newEmail)
    let [oldEmailRow, newEmailRow] = await Promise.all([oldEmailPromise, newEmailPromise])
    if(newEmailRow) throw service.error('taken')
    if(!oldEmailRow) throw service.error('notFound')
    emit('emailPassword', [{
      type: 'EmailPasswordCreated',
      emailPassword: emailKey.newEmail,
      data: {
        email: emailKey.newEmail,
        user: emailKey.user,
        passwordHash: oldEmailRow.passwordHash
      }
    },{
      type: 'EmailPasswordDeleted',
      emailPassword: emailKey.oldEmail
    },{
      type: "keyUsed",
      key
    }])
    emit("user", [{
      type: "loginMethodAdded",
      user: emailKey.user,
      method: {
        type: "emailPassword",
        id: emailKey.newEmail,
        email: emailKey.newEmail
      }
    }, {
      type: "loginMethodRemoved",
      user: emailKey.user,
      method: {
        type: "emailPassword",
        id: emailKey.oldEmail,
        email: emailKey.oldEmail
      }
    }])
  }
})
