const app = require('./app.js')
const definition = require("./definition.js")

const {User, EmailPassword} = require("./model.js")

definition.action({
  name: "EmailPasswordUserCreate", // create user with emailPassword
  properties: {
    email: EmailPassword.properties.email,
    passwordHash: EmailPassword.properties.passwordHash
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ email, passwordHash }, context, emit) {
    const emailRow = await EmailPassword.get(email)
    if(emailRow) throw new Error("alreadyAdded")
    let user = app.generateUid()
    emit({
      type: "EmailPasswordCreated",
      emailPassword: email,
      data: {
        email, passwordHash, user
      }
    })
    emit("users", [{
      type: "UserCreated",
      user
    },{
      type: "loginMethodAdded",
      user,
      method: {
        type: "emailPassword",
        id: email,
        email
      }
    }])
    return user
  }
})

definition.action({
  name: "EmailPasswordCreate", // override CRUD operation
  properties: {
    ...EmailPassword.properties,
    user: {
      type: User,
      idOnly: true
    }
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ email, passwordHash, user }, context, emit) {
    const emailRow = await EmailPassword.get(email)
    const userRow = await User.get(user)
    if(emailRow) throw new Error("alreadyAdded")
    if(!userRow) throw new Error("userNotFound")
    emit({
      type: "EmailPasswordCreated",
      emailPassword: email,
      data: {
        email, passwordHash, user
      }
    })
    emit("users", {
      type: "loginMethodAdded",
      user,
      method: {
        type: "emailPassword",
        id: email,
        email
      }
    })
    return email
  }
})

definition.action({
  name: "EmailPasswordUpdate", // override CRUD operation
  properties: {
    emailPassword: {
      type: EmailPassword,
      idOnly: true
    },
    passwordHash: EmailPassword.properties.passwordHash
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ emailPassword, passwordHash }, { client, service }, emit) {
    const emailRow = await EmailPassword.get(emailPassword)
    if(!emailRow) throw 'notFound'
    /*emit([{
      type: "EmailPasswordUpdated",
      emailPassword,
      data: {
        passwordHash: passwordHash
      }
    }])*/
    service.trigger({
      type: "OnPasswordChange",
      user: emailRow.user,
      passwordHash
    })
    return emailPassword
  }
})

definition.action({
  name: "EmailPasswordDelete", // override CRUD operation
  properties: {
    emailPassword: {
      type: EmailPassword,
      idOnly: true
    },
    passwordHash: EmailPassword.properties.passwordHash
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ emailPassword }, context, emit) {
    const emailRow = await EmailPassword.get(emailPassword)
    if(!emailRow) throw 'notFound'
    console.log("EMAIL ROW", emailRow)
    const userRow = await User.get(emailRow.user)
    if(!userRow) throw new Error("userNotFound")
    emit({
      type: "EmailPasswordDeleted",
      emailPassword
    })
    emit("users", {
      type: "loginMethodRemoved",
      user: emailRow.user,
      method: {
        type: "emailPassword",
        id: emailPassword,
        email: emailPassword
      }
    })
    return emailPassword
  }
})

definition.event({
  name: "UserDeleted",
  properties: {
    user: {
      type: User,
      idOnly: true
    }
  },
  async execute({ user }, { service }) {
    await app.dao.request(['database', 'query', app.databaseName, `(${
      async (input, output, { user }) =>
        await input.table("emailPassword_EmailPassword").onChange((obj, oldObj) => {
          if(obj && obj.user == user) output.table("emailPassword_EmailPassword").delete(obj.id)
        })
    })`, { user }])
  }
})

definition.trigger({
  name: "UserDeleted",
  properties: {
    user: {
      type: User,
      idOnly: true
    }
  },
  async execute({ user }, context, emit) {
    emit({
      type: "UserDeleted",
      user
    })
  }
})
