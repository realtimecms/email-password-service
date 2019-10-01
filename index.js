const r = require.main.rethinkdb || require('rethinkdb')
if (require.main === module) require.main.rethinkdb = r

const rtcms = require("realtime-cms")
const definition = require("./definition.js")

require("./crud.js")

require("./register.js")
require("./login.js")

require("./emailChange.js")
require("./passwordChange.js")

module.exports = definition

async function start() {
  rtcms.processServiceDefinition(definition, [ ...rtcms.defaultProcessors ])
  await rtcms.updateService(definition)//, { force: true })
  const service = await rtcms.startService(definition, { runCommands: true, handleEvents: true })

  rtcms.connectToDatabase().then(db => require("../config/metricsWriter.js")(db, definition.name, () => ({

  })))
}

if (require.main === module) start().catch( error => { console.error(error); process.exit(1) })

