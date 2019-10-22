const globalValidators = require("../validation")
const { EmailPassword, EmailKey } = require("./model.js")

const validators = {
  ...globalValidators,
  newUserEmail: (settings) => async (email, { service, cms }) => {
    let emailPasswordPromise = EmailPassword.get(email)
    let registerKeysPromise = EmailKey.run(EmailKey.table
        .filter({ action: 'register',  used: false, email })
        .filter(r=>r("expire").gt(Date.now())) /// TODO: use index
    ).then(cursor => {
      if(!cursor) return []
      return cursor.toArray()
    })
    const [emailRow, registerKeys] =
        await Promise.all([emailPasswordPromise, registerKeysPromise])
    if(emailRow) return "alreadyAdded"
    if(registerKeys.length>0) return "registrationNotConfirmed"
  }
}

module.exports = validators
