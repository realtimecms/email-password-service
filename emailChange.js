const crypto = require('crypto')
const definition = require("./definition.js")

const { User, EmailPassword, EmailKey } = require("./model.js")

const passwordHash = require('../config/passwordHash.js')

require('../../i18n/ejs-require.js')
const i18n = require('../../i18n')

definition.action({
  name: "startEmailChange",
  properties: {
    newEmail: EmailPassword.properties.email,
    passwordHash: EmailPassword.properties.passwordHash,
    lang: { type: String, validation: ['nonEmpty'] }
  },
  async execute({ newEmail, passwordHash, lang }, {client, service}, emit) {
    if(!client.user) throw new Error("notAuthorized")
    const user = client.user
    let oldEmailPromise = (service.dao.get(['database', 'query', service.databaseName, `(${
        async (input, output, { user }) =>
            await input.table("emailPassword_EmailPassword").onChange((obj, oldObj) => {
              if(obj && obj.user == user) output.put(obj)
            })
    })`, { user }])).then(v => v[0])
    let newEmailPromise = EmailPassword.get(newEmail)
    let randomKeyPromise = new Promise((resolve, reject) =>
        crypto.randomBytes(16, (err, buf) => {
          if(err) reject(err)
          resolve(buf.toString('hex')+(crypto.createHash('sha256')
              .update(user + newEmail).digest('hex').slice(0,8)))
        })
    )
    let userPromise = User.get(user)
    let [oldEmailRow, newEmailRow, randomKey, userRow] =
        await Promise.all([oldEmailPromise, newEmailPromise, randomKeyPromise, userPromise])
    if(!oldEmailRow) throw 'notFound'
    if(newEmailRow) throw { properties: { newEmail: "taken" } }
    if(oldEmailRow.user != user) throw new Error('notAuthorized')
    if(oldEmailRow.passwordHash != passwordHash) throw { properties: { passwordHash: "wrongPassword" }}
    let oldEmail = oldEmailRow.email
    emit("emailPassword", {
      type: 'keyGenerated',
      action: 'emailChange',
      oldEmail, newEmail, user,
      key: randomKey,
      expire: Date.now() + (24 * 60 * 60 * 1000)
    })
    const i18nLang = i18n.languages[lang] || i18n()
    emit("email", {
      type: "sent",
      email: i18nLang.emailPassword.changeEmailEmail({oldEmail, newEmail, key: randomKey, user: userRow})
    })
  }
})

definition.action({
  name: "finishEmailChange",
  properties: {
    key: { type: String }
  },
  async execute({ key }, {client, service}, emit) {
    let emailKey = await EmailKey.get(key)
    if(!emailKey) throw 'notFound'
    if(emailKey.action != 'emailChange') throw 'notFound'
    if(emailKey.used) throw new Error('used')
    if(emailKey.expire < Date.now()) throw new Error('expired')
    let oldEmailPromise = EmailPassword.get(emailKey.oldEmail)
    let newEmailPromise = EmailPassword.get(emailKey.newEmail)
    let [oldEmailRow, newEmailRow] = await Promise.all([oldEmailPromise, newEmailPromise])
    if(newEmailRow) throw new Error('taken')
    if(!oldEmailRow) throw 'notFound'
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
