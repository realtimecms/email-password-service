const app = require("@live-change/framework").app()

const definition = require("./definition.js")
definition.validators = require("./validation.js")
const autoSecurityProcessor = require('../security-service/autoSecurity.js')

require("./crud.js")

require("./register.js")
require("./login.js")

require("./emailChange.js")
require("./passwordChange.js")

module.exports = definition

async function start() {
  if(!app.dao) {
    await require('@live-change/server').setupApp({})
    await require('@live-change/elasticsearch-plugin')(app)
  }

  app.processServiceDefinition(definition, [ ...app.defaultProcessors, autoSecurityProcessor ])
  await app.updateService(definition)//, { force: true })
  const service = await app.startService(definition, { runCommands: true, handleEvents: true })

  /*require("../config/metricsWriter.js")(definition.name, () => ({

  }))*/
}

if (require.main === module) start().catch( error => { console.error(error); process.exit(1) })
