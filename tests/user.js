const test = require('blue-tape')
const r = require('rethinkdb')
const testUtils = require('rethink-event-sourcing/tape-test-utils.js')
const crypto = require('crypto')

const admin = {
  roles: ["admin"]
}

test('User operations - Register, login, logout, reset password, change email...', t => {
  t.plan(13)

  let conn

  testUtils.connectToDatabase(t, r, (connection) => conn = connection)

  let sessionId = crypto.randomBytes(24).toString('hex')
  let passwordHash = crypto.randomBytes(12).toString('hex')
  let email = "testEmail_" + (Math.random() * 1000000) + "@test.com"
  let firstName = crypto.randomBytes(12).toString('hex')
  let lastName = crypto.randomBytes(12).toString('hex')
  let phoneNumber = crypto.randomBytes(12).toString('hex')
  let userData = { firstName, lastName, phoneNumber }
  let userId
  let commandId
  let registerKey

  t.test("Start sign-up", t => {
    t.plan(3)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'startRegister',
      parameters: { email, passwordHash, userData }
    }, (cId) => { commandId = cId }).then(result => {})

    t.test('Check if there are events generated', t => {
      t.plan(4)

      setTimeout(() => {
        testUtils.getGeneratedEvents(r, 'emailPassword', commandId,
          (events) => {
            t.equal(events.length, 1, "generated one event in emailPassword list")
            if (events[0].key) {
              registerKey = events[0].key
              t.pass('found key in event')
            } else t.fail('key not found')
            if (events[0].user) {
              userId = events[0].user
              t.pass('found userId in event')
            } else t.fail('userId not found')
          }
        )

        testUtils.getGeneratedEvents(r, 'email', commandId,
          (events) => {
            t.equal(events.length, 1, "generated email event in email list")
          }
        )
      }, 350)
    })

    t.test('Check if there are registerKey', t => {
      t.plan(1)
      setTimeout(() => {
        r.table('emailPassword_EmailKey').get(registerKey).run(conn).then(
          row => {
            if(row && row.email == email) {
              t.pass("register key found")
            } else t.fail("register key not found")
          }
        )
      }, 450)
    })

  })

  t.test("resend sign-up key", t => {
    t.plan(2)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'resendRegisterKey',
      parameters: { email }
    }, (cId) => { commandId = cId }).then(result => {})

    setTimeout(()=>{
      testUtils.getGeneratedEvents(r, 'email', commandId,
        (events) => {
          t.equal(events.length, 1, "generated email event in email list")
        }
      )
    }, 550)
  })

  t.test("finish sign-up using email key", t => {
    t.plan(5)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'finishRegister',
      parameters: { key: registerKey }
    }, (cId) => { commandId = cId }).then(result => {})

    t.test('Check if there are events generated', t => {
      t.plan(2)

      setTimeout(() => {
        testUtils.getGeneratedEvents(r, 'emailPassword', commandId,
          (events) => t.equal(events.length, 2, "generated two events in emailPassword list"))

        testUtils.getGeneratedEvents(r, 'users', commandId,
          (events) => t.equal(events.length, 2, "generated two events in user list"))
      }, 150)
    })

    t.test('Check if there are emailPassword entry', t => {
      t.plan(1)
      r.table("emailPassword_EmailPassword").get(email).run(conn).then(
        row => {
          if (row) t.pass("email found " + JSON.stringify(row))
          else t.fail("email not found " + email)
        }
      ).catch(
        error => t.fail("error " + error)
      )
    })

    t.test('Check if there are user entry', t => {
      t.plan(1)
      r.table("users_User").get(userId).run(conn).then(
        row => {
          if (row) t.pass("user found " + JSON.stringify(row))
          else t.fail("user not found " + userId)
        }
      ).catch(
        error => t.fail("error " + error)
      )
    })

    t.test('Check if the user has login method', t => {
      t.plan(4)
      r.table("users_User").get(userId).run(conn).then(
        user => {
          t.equal(user.loginMethods.length, 1, "user has one login method")
          t.equal(user.loginMethods[0].type, 'emailPassword', "login method type match")
          t.equal(user.loginMethods[0].id, email, "login method id match")
          t.equal(user.loginMethods[0].email, email, "login method extra data match")
        }
      ).catch(
        error => t.fail("error " + error)
      )
    })
  })

  t.test('Login with email and password', t => {
    t.plan(3)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'login',
      parameters: {
        email: email,
        passwordHash: passwordHash,
      },
      client: {
        sessionId: sessionId
      }
    }, (cId) => commandId = cId)

    t.test('Check if there are events generated', t => {
      t.plan(2)

      setTimeout(()=>{
        testUtils.getGeneratedEvents(r, 'session', commandId,
          (events) => {
            t.equal(events.length, 1, "generated one event in session list")
            t.equal(events[0].type, "loggedIn", "event is logged in event")
          })
      }, 250)
    })

    t.test('check if logged in', t=> {
      t.plan(2)
      setTimeout(()=>{
        r.table('session').get(sessionId).run(conn).then(
          session => {
            if(!session) t.fail("session not found")
            t.equal(session.user, userId, 'user id match')
            t.pass('logged in')
          }
        ).catch(t.fail)
      }, 150)
    })
  })


  let newPasswordHash

  t.test('change password by user', t => {
    t.plan(2)

    newPasswordHash = crypto.randomBytes(12).toString('hex')

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'updatePasswordByUser',
      parameters: {
        user: userId,
        email: email,
        oldPasswordHash: passwordHash,
        newPasswordHash: newPasswordHash
      }
    }, (cId) => { }).then(result => {})

    t.test('Check if the password is changed', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("emailPassword_EmailPassword").get(email).run(conn).then(
          row => {
            t.equal(row.passwordHash, newPasswordHash, "password hash match")
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 350)
    })
  })

  t.test('change all passwords by user', t => {
    t.plan(2)

    let newPasswordHash2 = crypto.randomBytes(12).toString('hex')

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'updateAllPasswordsByUser',
      parameters: {
        user: userId,
        oldPasswordHash: newPasswordHash,
        newPasswordHash: newPasswordHash2
      }
    }, (cId) => { }).then(result => {})

    t.test('Check if the password is changed', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("emailPassword_EmailPassword").get(email).run(conn).then(
          row => {
            t.equal(row.passwordHash, newPasswordHash2, "password hash match")
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 350)
    })
  })

  let resetPasswordKey

  t.test('generate reset password email', t => {
    t.plan(3)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'startPasswordReset',
      parameters: { email: email }
    }, (cId) => { commandId = cId }).then(result => {})

    t.test('Check if there are events generated', t => {
      t.plan(3)

      setTimeout(()=>{
        testUtils.getGeneratedEvents(r, 'emailPassword', commandId,
          (events) => {
            t.equal(events.length, 1, "generated one event in emailPassword list")
            if(events[0].key) {
              resetPasswordKey = events[0].key
              t.pass('found key in event')
            } else t.fail('key not found')
          })
      }, 350)

      setTimeout(()=>{
        testUtils.getGeneratedEvents(r, 'email', commandId,
          (events) => {
            t.equal(events.length, 1, "generated email event in email list")
          }
        )
      }, 350)
    })

    t.test('Check if there are resetKey', t => {
      t.plan(1)
      setTimeout(() => {
        r.table('emailPassword_EmailKey').get(resetPasswordKey).run(conn).then(
          row => {
            if(row && row.email == email) {
              t.pass("reset key found")
            } else t.fail("reset key not found")
          }
        )
      }, 350)
    })
  })

  let newPasswordHash3 = crypto.randomBytes(12).toString('hex')

  t.test("Reset password using email key", t => {
    t.plan(2)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'finishPasswordReset',
      parameters: {
        newPasswordHash: newPasswordHash3,
        key: resetPasswordKey
      }
    }, (cId) => { }).then(result => {})

    t.test('Check if the password is changed', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("emailPassword_EmailPassword").get(email).run(conn).then(
          row => {
            t.equal(row.passwordHash, newPasswordHash3, "password hash match")
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 350)
    })
  })

  let newEmail = "testEmail_" + (Math.random() * 1000000) + "@test.com"
  let changeEmailKey

  t.test('generate change email email', t => {
    t.plan(3)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'startEmailChange',
      parameters: {
        newEmail: newEmail,
        passwordHash: newPasswordHash3
      },
      client: {
        user: userId
      }
    }, (cId) => { commandId = cId }).then(result => {})

    t.test('Check if there are events generated', t => {
      t.plan(3)

      setTimeout(()=>{
        testUtils.getGeneratedEvents(r, 'emailPassword', commandId,
          (events) => {
            t.equal(events.length, 1, "generated one event in emailPassword list")
            if(events[0].key) {
              changeEmailKey = events[0].key
              t.pass('found key in event')
            } else t.fail('key not found')
          })
      }, 350)

      setTimeout(()=>{
        testUtils.getGeneratedEvents(r, 'email', commandId,
          (events) => {
            t.equal(events.length, 1, "generated email event in email list")
          }
        )
      }, 350)
    })

    t.test('Check if there are resetKey', t => {
      t.plan(3)
      setTimeout(() => {
        r.table('emailPassword_EmailKey').get(changeEmailKey).run(conn).then(
          row => {
            if(row) {
              t.pass("reset key found")
              t.equal(row.newEmail, newEmail, "newEmail match")
              t.equal(row.oldEmail, email, "email match")
            } else t.fail("reset key not found")
          }
        )
      }, 350)
    })
  })

  t.test("Change email using email key", t => {
    t.plan(2)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'finishEmailChange',
      parameters: {
        key: changeEmailKey
      }
    }, (cId) => { }).then(result => {})

    t.test('Check if the email is changed to '+newEmail, t => {
      t.plan(1)
      setTimeout(() => {
        let oldEmailPromise = r.table("emailPassword_EmailPassword").get(email).run(conn)
        let newEmailPromise = r.table("emailPassword_EmailPassword").get(newEmail).run(conn)
        Promise.all([oldEmailPromise, newEmailPromise]).then(
          ([oldEmailRow, newEmailRow]) => {
            if(oldEmailRow) return t.fail("old email still exists")
            if(!newEmailRow) return t.fail("new email not found")
            t.pass("email changed")
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 350)
    })
  })

  t.test('delete user and check if login method is deleted too', t => {
    t.plan(2)

    testUtils.runCommand(t, r, 'users', {
      type: 'UserDelete',
      client: admin,
      parameters: { user: userId }
    }, (cId) => { }).then(result => {})

    t.test('Check if emailPassword entry are removed', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("emailPassword_EmailPassword").get(newEmail).run(conn).then(
          row => {
            if (!row) t.pass("email not found")
            else t.fail("email found " + JSON.stringify(row))
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 1250)
    })

  })

  t.test('close connection', t => {
    conn.close(() => {
      t.pass('closed')
      t.end()
    })
  })

})