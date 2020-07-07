const definition = require("./definition.js")

const User = definition.foreignModel("users", "User")

const passwordHash = require('../config/passwordHash.js')

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

module.exports = {
  User, EmailPassword, EmailKey
}