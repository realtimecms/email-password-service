const definition = require("./definition.js")

const { User, EmailPassword, EmailKey } = require("./model.js")

const passwordHash = require("../config/passwordHash.js")

definition.action({
  name: "login",
  properties: {
    email: EmailPassword.properties.email,
    passwordHash: EmailPassword.properties.passwordHash,
  },
  autoSecurity: true,
  async execute({ email, passwordHash }, {service, client}, emit) {
    const registerKeyPromise = (service.dao.get(['database', 'query', service.databaseName, `(${
        async (input, output, { email }) =>
            await input.table("emailPassword_EmailKey").onChange((obj, oldObj) => {
              if(obj && obj.action == 'register' && !obj.used 
                  && obj.email == email && obj.expire > Date.now()) output.put(obj)
            })
    })`, { email }])).then(v => v[0])
    let emailPasswordPromise = EmailPassword.get(email)
    let [registerKeyRow, emailPasswordRow] = await Promise.all([registerKeyPromise, emailPasswordPromise])
    if(!emailPasswordRow && registerKeyRow) throw "registrationNotConfirmed"
    if (!emailPasswordRow) {
      await service.trigger({
        type: "securityEvent",
        event: {
          type: "login-failed",
          keys: { ip: client.ip, session: client.session, user: client.user }
        }
      })
      throw "notFound"
    }
    if(emailPasswordRow.passwordHash != passwordHash) {
      await service.trigger({
        type: "securityEvent",
        event: {
          type: "login-failed",
          keys: { ip: client.ip, session: client.session, user: client.user }
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
