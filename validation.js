const globalValidators = require("../validation")
const { EmailPassword, EmailKey } = require("./model.js")

const validators = {
  ...globalValidators,
  newUserEmail: (settings) => async (email, context) => {
    const { service, app } = context
    const emailPasswordPromise = EmailPassword.get(email)
    console.log("service", service.constructor.name)
    const registerKeysPromise = (app.dao.get(['database', 'query', app.databaseName, `(${
        async (input, output, { email }) =>
            await input.table("emailPassword_EmailKey").onChange((obj, oldObj) => {
              if(obj && obj.action == 'register' && !obj.used
                  && obj.email == email && obj.expire > Date.now()) output.put(obj)
            })
    })`, { email }]))
    const [emailRow, registerKeys] =
        await Promise.all([emailPasswordPromise, registerKeysPromise])
    if(emailRow) return "alreadyAdded"
    if(registerKeys.length > 0) return "registrationNotConfirmed"
  }
}

module.exports = validators
