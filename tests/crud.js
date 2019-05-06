const test = require('blue-tape')
const r = require('rethinkdb')
const testUtils = require('rethink-event-sourcing/tape-test-utils.js')
const crypto = require('crypto')

const admin = {
  roles: ["admin"]
}

test('CRUD operations', t => {
  t.plan(7)

  let conn

  testUtils.connectToDatabase(t, r, (connection) => conn = connection)

  let sessionId = crypto.randomBytes(24).toString('hex')
  let passwordHash = crypto.randomBytes(12).toString('hex')
  let email = "testEmail_" + (Math.random() * 1000000) + "@test.com"
  let userId
  let commandId

  t.test('Create email-password user', t => {
    t.plan(6)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'EmailPasswordUserCreate',
      parameters: {
        email: email,
        passwordHash: passwordHash
      }
    }, (cId) => commandId = cId).then(
      result => {
        userId = result
      }
    )

    t.test('Check if userId is generated', t => {
      t.plan(1)
      if (userId) t.pass("received user id " + userId)
      else t.fail('no user id')
    })

    t.test('Check if there are events generated', t => {
      t.plan(2)

      setTimeout(() => {
        testUtils.getGeneratedEvents(r, 'emailPassword', commandId,
          (events) => t.equal(events.length, 1, "generated one event in emailPassword list"))

        testUtils.getGeneratedEvents(r, 'users', commandId,
          (events) => t.equal(events.length, 2, "generated two events in users list"))
      }, 250)
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

  t.test('remove login method from user', t => {
    t.plan(3)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'EmailPasswordDelete',
      parameters: {
        emailPassword: email
      }
    }, (cId) => {
    }).then(result => {
    })

    t.test('Check if the user has no login method', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("users_User").get(userId).run(conn).then(
          user => {
            t.equal(user.loginMethods.length, 0, "user has no one login method")
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 100)
    })

    t.test('Check if emailPassword entry are removed', t => {
      t.plan(1)
      r.table("emailPassword_EmailPassword").get(email).run(conn).then(
        row => {
          if (!row) t.pass("email not found")
          else t.fail("email found " + JSON.stringify(row))
        }
      ).catch(
        error => t.fail("error " + error)
      )
    })

  })

  t.test('add login method to user', t => {
    t.plan(3)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'EmailPasswordCreate',
      parameters: {
        email,
        passwordHash,
        user: userId,
      }
    }, (cId) => {
    }).then(result => {
    })

    t.test('Check if there are emailPassword entry', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("emailPassword_EmailPassword").get(email).run(conn).then(
          row => {
            if (row) t.pass("email found " + JSON.stringify(row))
            else t.fail("email not found " + email)
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 100)
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

  let newPasswordHash = crypto.randomBytes(12).toString('hex')

  t.test('change password', t => {
    t.plan(2)

    testUtils.runCommand(t, r, 'emailPassword', {
      type: 'EmailPasswordUpdate',
      parameters: {
        emailPassword: email,
        passwordHash: newPasswordHash
      }
    }, (cId) => {
    }).then(result => {
    })

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
      }, 150)
    })
  })

  t.test('delete user and check if login method is deleted too', t => {
    t.plan(2)

    testUtils.runCommand(t, r, 'users', {
      type: 'UserDelete',
      parameters: {
        user: userId
      },
      client: admin
    }, (cId) => {
    }).then(result => {
    })

    t.test('Check if emailPassword entry are removed', t => {
      t.plan(1)
      setTimeout(() => {
        r.table("emailPassword_EmailPassword").get(email).run(conn).then(
          row => {
            if (!row) t.pass("email not found")
            else t.fail("email found " + JSON.stringify(row))
          }
        ).catch(
          error => t.fail("error " + error)
        )
      }, 850)
    })

  })

  t.test('close connection', t => {
    conn.close(() => {
      t.pass('closed')
      t.end()
    })
  })

})