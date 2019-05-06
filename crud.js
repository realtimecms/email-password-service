const rtcms = require("../../RTCms")
const definition = require("./definition.js")

const {User, EmailPassword} = require("./model.js")

definition.action({
  name: "EmailPasswordUserCreate", // create user with emailPassword
  properties: {
    email: {
      type: String
    },
    passwordHash: {
      type: String
    }
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ email, passwordHash }, context, emit) {
    const emailRow = await EmailPassword.get(email)
    if(emailRow) throw new Error("alreadyAdded")
    let user = rtcms.generateUid()
    emit([{
      type: "EmailPasswordCreated",
      emailPassword: email,
      data: {
        email, passwordHash, user
      }
    }])
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
    email: {
      type: String
    },
    passwordHash: {
      type: String
    },
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
    emit([{
      type: "EmailPasswordCreated",
      emailPassword: email,
      data: {
        email, passwordHash, user
      }
    }])
    emit("users", [{
      type: "loginMethodAdded",
      user,
      method: {
        type: "emailPassword",
        id: email,
        email
      }
    }])
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
    passwordHash: {
      type: String
    }
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ emailPassword, passwordHash }, context, emit) {
    const emailRow = await EmailPassword.get(emailPassword)
    if(!emailRow) throw new Error("notFound")
    emit([{
      type: "EmailPasswordUpdated",
      emailPassword,
      data: {
        passwordHash: passwordHash
      }
    }])
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
    passwordHash: {
      type: String
    }
  },
  returns: {
    type: EmailPassword,
    idOnly: true
  },
  async execute({ emailPassword }, context, emit) {
    const emailRow = await EmailPassword.get(emailPassword)
    if(!emailRow) throw new Error("notFound")
    console.log("EMAIL ROW", emailRow)
    const userRow = await User.get(emailRow.user)
    if(!userRow) throw new Error("userNotFound")
    emit([{
      type: "EmailPasswordDeleted",
      emailPassword
    }])
    emit("users", [{
      type: "loginMethodRemoved",
      user: emailRow.user,
      method: {
        type: "emailPassword",
        id: emailPassword,
        email: emailPassword
      }
    }])
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
  async execute({ user }) {
    await EmailPassword.run(EmailPassword.table.filter({ user }).delete())
  }
})

definition.trigger({
  name: "OnUserDelete",
  properties: {
    user: {
      type: User,
      idOnly: true
    }
  },
  async execute({ user }, context, emit) {
    emit([{
      type: "UserDeleted",
      user
    }])
  }
})
