const rtcms = require("realtime-cms")
const definition = require("./definition.js")

const {User, EmailPassword, EmailKey} = require("./model.js")

const passwordHash = require("./passwordHash.js")

definition.action({
  name: "login",
  properties: {
    email: { type: String },
    passwordHash: { type: String, preFilter: passwordHash }
  },
  async execute({ email, passwordHash }, {service, client}, emit) {
    let registerKeyPromise = EmailKey.run(EmailKey.table
      .filter({ action: 'register',  used: false, email })
      .filter(r=>r("expire").gt(Date.now())))
        .then(cursor => {
          if(!cursor) return [];
          return cursor.toArray().then( arr => arr[0] );
        })
    let emailPasswordPromise = EmailPassword.get(email)
    let [registerKeyRow, emailPasswordRow] = await Promise.all([registerKeyPromise, emailPasswordPromise])
    if(!emailPasswordRow && registerKeyRow) throw service.error("registrationNotConfirmed")
    if (!emailPasswordRow) throw service.error("notFound")
    if(emailPasswordRow.passwordHash != passwordHash) throw service.error("wrongPassword")
    let userRow = await User.get(emailPasswordRow.user)
    if(!userRow) throw service.error("internalServerError")
    emit("session", [{
      type: "loggedIn",
      user: emailPasswordRow.user,
      session: client.sessionId,
      expire: null,
      roles: userRow.roles || []
    }])
  }
})
